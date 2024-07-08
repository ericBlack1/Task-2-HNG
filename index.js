const express = require('express');
const bcrypt = require('bcrypt');
const pg = require('pg');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

if (!process.env.JWT_SECRET) {
  console.error('JWT_SECRET is not defined in the environment variables');
  process.exit(1);
}

const app = express();
const port = process.env.PORT || 3001;

app.use(express.json());

const pool = new pg.Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

app.post("/auth/register", async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { firstName, lastName, email, password, phone } = req.body;
    if (!firstName || !lastName || !email || !password || !phone) {
      return res.status(400).json({
        status: "Bad request",
        message: "Registration unsuccessful",
        statusCode: 400
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const userResult = await client.query(
      'INSERT INTO "User" (firstName, lastName, email, password, phone) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [firstName, lastName, email, hashedPassword, phone]
    );

    const user = userResult.rows[0];  // Here we correctly define user
    const userId = user.userid;
    const orgName = `${firstName}'s Organisation`;

    const orgResult = await client.query(
      'INSERT INTO "Organization" (name) VALUES ($1) RETURNING *',
      [orgName]
    );

    const orgId = orgResult.rows[0].orgid;

    await client.query(
      'INSERT INTO "UserOrganization" (userId, orgId) VALUES ($1, $2)',
      [userId, orgId]
    );

    const accessToken = jwt.sign({ userId: user.userid }, process.env.JWT_SECRET, { expiresIn: '1h' });

    await client.query('COMMIT');

    res.status(201).json({
      status: "success",
      message: "Registration successful",
      data: {
        accessToken,
        user: {
          userId,
          firstName,
          lastName,
          email,
          phone
        }
      }
    });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(400).json({
      status: "Bad request",
      message: "Registration unsuccessful",
      statusCode: 400
    });
  } finally {
    client.release();
  }
});

app.post("/auth/login", async (req, res) => {
  const client = await pool.connect();
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(401).json({
        status: "Bad request",
        message: "Authentication failed",
        statusCode: 401
      });
    }

    const userResult = await client.query(
      'SELECT * FROM "User" WHERE email = $1',
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        status: "Bad request",
        message: "Authentication failed",
        statusCode: 401
      });
    }

    const user = userResult.rows[0];

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        status: "Bad request",
        message: "Authentication failed",
        statusCode: 401
      });
    }

    const accessToken = jwt.sign({ userId: user.userid }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({
      status: "success",
      message: "Login successful",
      data: {
        accessToken,
        user: {
          userId: user.userid,
          firstName: user.firstname,
          lastName: user.lastname,
          email: user.email,
          phone: user.phone
        }
      }
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Server Error");
  } finally {
    client.release();
  }
});

app.get("/api/users/:id", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const userId = req.params.id;
    const loggedInUserId = req.user.userId;

    // Check if the logged-in user has access to the requested user record
    const userAccessResult = await client.query(
      `SELECT u.*
      FROM "User" u
      JOIN "UserOrganization" uo ON u.userid = uo.userId
      JOIN "Organization" o ON uo.orgId = o.orgid
      WHERE u.userid = $1 AND (uo.userId = $2 OR EXISTS (
        SELECT 1
        FROM "UserOrganization" uo2
        WHERE uo2.orgId = o.orgid AND uo2.userId = $2
      ))`,
      [userId, loggedInUserId]
    );

    if (userAccessResult.rows.length === 0) {
      return res.status(403).json({
        status: "Forbidden",
        message: "You do not have access to this user record",
        statusCode: 403
      });
    }

    const user = userAccessResult.rows[0];
    res.status(200).json({
      status: "success",
      message: "User record retrieved successfully",
      data: {
        userId: user.userid,
        firstName: user.firstname,
        lastName: user.lastname,
        email: user.email,
        phone: user.phone
      }
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Server Error");
  } finally {
    client.release();
  }
});

app.get("/api/organisations", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const loggedInUserId = req.user.userId;

    const orgAccessResult = await client.query(
      `SELECT o.*
       FROM "Organization" o
       JOIN "UserOrganization" uo ON o.orgid = uo.orgId
       WHERE uo.userId = $1`,
      [loggedInUserId]
    );    

    if (orgAccessResult.rows.length === 0) {
      return res.status(404).json({
        status: "Not Found",
        message: "No organizations found for the user",
        statusCode: 404
      });
    }

    const organizations = orgAccessResult.rows.map(org => ({
      orgId: org.orgid,
      name: org.name,
      description: org.description
    }));

    res.status(200).json({
      status: "success",
      message: "Organizations retrieved successfully",
      data: {
        organizations
      }
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Server Error");
  } finally {
    client.release();
  }
});

app.get("/api/organisations/:orgId", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const orgId = req.params.orgId;
    const loggedInUserId = req.user.userId;

    const orgAccessResult = await client.query(
      `SELECT o.*
       FROM "Organization" o
       JOIN "UserOrganization" uo ON o.orgid = uo.orgId
       WHERE o.orgid = $1 AND uo.userId = $2`,
      [orgId, loggedInUserId]
    );    

    if (orgAccessResult.rows.length === 0) {
      return res.status(403).json({
        status: "Forbidden",
        message: "You do not have access to this organization record",
        statusCode: 403
      });
    }

    const organization = orgAccessResult.rows[0];
    res.status(200).json({
      status: "success",
      message: "Organization record retrieved successfully",
      data: {
        orgId: organization.orgid,
        name: organization.name,
        description: organization.description
      }
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Server Error");
  } finally {
    client.release();
  }
});

app.post("/api/organisations", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { name, description } = req.body;
    const loggedInUserId = req.user.userId;

    if (!name) {
      return res.status(400).json({
        status: "Bad request",
        message: "Name is required and cannot be null",
        statusCode: 400
      });
    }

    const orgResult = await client.query(
      'INSERT INTO "Organization" (name, description) VALUES ($1, $2) RETURNING *',
      [name, description]
    );

    const organization = orgResult.rows[0];
    const orgId = organization.orgid;

    await client.query(
      'INSERT INTO "UserOrganization" (userId, orgId) VALUES ($1, $2)',
      [loggedInUserId, orgId]
    );

    res.status(201).json({
      status: "success",
      message: "Organisation created successfully",
      data: {
        orgId: organization.orgid,
        name: organization.name,
        description: organization.description
      }
    });
  } catch (error) {
    console.error(error.message);
    res.status(400).json({
      status: "Bad Request",
      message: "Client error",
      statusCode: 400
    });
  } finally {
    client.release();
  }
});

app.post("/api/organisations/:orgId/users", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { userId } = req.body;
    const orgId = req.params.orgId;
    const loggedInUserId = req.user.userId; // Get logged-in user's ID from decoded token

    // Check if required fields are present
    if (!userId) {
      return res.status(400).json({
        status: "Bad Request",
        message: "Client error",
        statusCode: 400
      });
    }

    // Check if the organisation exists
    const orgResult = await client.query('SELECT * FROM "Organization" WHERE orgid = $1', [orgId]);
    if (orgResult.rows.length === 0) {
      return res.status(404).json({
        status: "Not Found",
        message: "Organisation not found",
        statusCode: 404
      });
    }

    // Check if the user exists
    const userResult = await client.query('SELECT * FROM "User" WHERE userid = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({
        status: "Not Found",
        message: "User not found",
        statusCode: 404
      });
    }

    // Check if the logged-in user has permission to add users to this organization
    const orgPermissionResult = await client.query(
      'SELECT * FROM "UserOrganization" WHERE userId = $1 AND orgId = $2',
      [loggedInUserId, orgId]
    );
    if (orgPermissionResult.rows.length === 0) {
      return res.status(403).json({
        status: "Forbidden",
        message: "You do not have permission to add users to this organisation",
        statusCode: 403
      });
    }

    // Add user to the organisation
    await client.query(
      'INSERT INTO "UserOrganization" (userId, orgId) VALUES ($1, $2)',
      [userId, orgId]
    );

    res.status(200).json({
      status: "success",
      message: "User added to organisation successfully",
    });
  } catch (error) {
    console.error(error.message);
    res.status(400).json({
      status: "Bad Request",
      message: "Client error",
      statusCode: 400
    });
  } finally {
    client.release();
  }
});

module.exports = app

app.listen(port, () => {
  console.log(`Postgresql database connected`);
});
