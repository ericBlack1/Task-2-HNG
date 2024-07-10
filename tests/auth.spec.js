const request = require('supertest');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const app = require('../index');

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: Number(process.env.DB_PORT),
});

describe('Token Generation', () => {
  it('should generate a token with correct user details and expiration time', async () => {
    const userId = 1;
    const token = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    expect(decoded.userId).toBe(userId);
    const expirationTime = new Date(decoded.exp * 1000);
    const currentTime = new Date();
    expect(expirationTime.getTime() - currentTime.getTime()).toBeLessThanOrEqual(3600000);
  });
});

describe('POST /api/auth/register', () => {
    beforeAll(async () => {
      const client = await pool.connect();
      await client.query('BEGIN');
      try {
        await client.query('TRUNCATE "UserOrganization", "User", "Organization" CASCADE');
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    });
  
    it('should register user successfully with default organization', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          firstName: 'glen',
          lastName: 'Doe',
          email: 'glen.doe@example.com',
          password: 'password',
          phone: '123456789'
        });

        if (res.status !== 201) {
          console.log(res.body);
        }
  
      expect(res.status).toBe(201);
      expect(res.body.data.user.firstName).toBe('glen');
      expect(res.body.data.user.lastName).toBe('Doe');
      expect(res.body.data.user.email).toBe('glen.doe@example.com');
      expect(res.body.data.user.phone).toBe('123456789');
      expect(res.body.data.accessToken).toBeTruthy();
    });
  
    it('should log the user in successfully', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'glen.doe@example.com',
          password: 'password'
        });
  
      expect(res.status).toBe(200);
      expect(res.body.data.user.email).toBe('glen.doe@example.com');
      expect(res.body.data.accessToken).toBeTruthy();
    });

    it('should fail to login with incorrect password', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'glen.doe@example.com',
          password: 'wrongpassword'
        });
  
      expect(res.status).toBe(401);
      expect(res.body.message).toBe('Authentication failed');
    });
  
    it('should fail if required fields are missing', async () => {
      const fields = ['firstName', 'lastName', 'email', 'password', 'phone'];
  
      for (const field of fields) {
        const userData = {
          firstName: 'glen',
          lastName: 'Doe',
          email: 'glen.doe@example.com',
          password: 'password',
          phone: '123456789'
        };
        delete userData[field];
  
        const res = await request(app)
          .post('/api/auth/register')
          .send(userData);
  
        expect(res.status).toBe(400);
        expect(res.body.message).toBe('Registration unsuccessful');
      }
    });
  
    it('should fail if there is a duplicate email', async () => {
      await request(app)
        .post('/api/auth/register')
        .send({
          firstName: 'Jane',
          lastName: 'Doe',
          email: 'jane.doe@example.com',
          password: 'password',
          phone: '123456789'
        });
  
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          firstName: 'Jane',
          lastName: 'Doe',
          email: 'jane.doe@example.com',
          password: 'password',
          phone: '123456789'
        });
  
      expect(res.status).toBe(400);
      expect(res.body.message).toBe('Registration unsuccessful');
    });
});

describe('GET /api/organisations', () => {
  let accessToken1, accessToken2, orgId;

  beforeAll(async () => {
    // Register and log in User 1
    await request(app)
      .post('/api/auth/register')
      .send({
        firstName: 'Alice',
        lastName: 'Smith',
        email: 'alice.smith@example.com',
        password: 'password1',
        phone: '1234567890'
      });
      
    let res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'alice.smith@example.com',
        password: 'password1'
      });
    accessToken1 = res.body.data.accessToken;

    // Register and log in User 2
    await request(app)
      .post('/api/auth/register')
      .send({
        firstName: 'Bob',
        lastName: 'Brown',
        email: 'bob.brown@example.com',
        password: 'password2',
        phone: '0987654321'
      });

    res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'bob.brown@example.com',
        password: 'password2'
      });
    accessToken2 = res.body.data.accessToken;

    // User 1 creates an organization
    res = await request(app)
      .post('/api/organisations')
      .set('Authorization', `Bearer ${accessToken1}`)
      .send({
        name: "Alice's Organization",
        description: 'Alice Organization Description'
      });

    orgId = res.body.data.orgId;
  });

  it('should ensure users cannot see data from organizations they do not have access to', async () => {
    const res = await request(app)
      .get(`/api/organisations/${orgId}`)
      .set('Authorization', `Bearer ${accessToken2}`);

    expect(res.status).toBe(403);
    expect(res.body.message).toBe('You do not have access to this organization record');
  });
});