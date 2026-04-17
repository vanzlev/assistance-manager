const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const port = 3000;
const saltRounds = 10;

// Middleware
app.use(cors());
app.use(express.json());

// Serve uploaded files statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// PostgreSQL connection (Supabase)
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

db.connect((err) => {
  if (err) {
    console.error('PostgreSQL connection failed:', err);
    return;
  }
  console.log('Connected to Supabase PostgreSQL database');
});

// Auto-update updated_at trigger function
db.query(`
  CREATE OR REPLACE FUNCTION update_updated_at_column()
  RETURNS TRIGGER AS $$
  BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
  END;
  $$ language 'plpgsql';
`).catch(() => {});

db.query(`
  DROP TRIGGER IF EXISTS update_assistance_requests_updated_at ON assistance_requests;
  CREATE TRIGGER update_assistance_requests_updated_at
  BEFORE UPDATE ON assistance_requests
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
`).catch(() => {});

// ==========================
// MULTER SETUP (File Uploads)
// ==========================

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const safeName = file.originalname.replace(/\s+/g, '_');
    cb(null, `${Date.now()}_${safeName}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|pdf|doc|docx/;
    const ext = allowed.test(path.extname(file.originalname).toLowerCase());
    if (ext) return cb(null, true);
    cb(new Error('Only images (jpg, png), PDFs, and Word documents are allowed'));
  }
});

// Test route
app.get('/', (req, res) => {
  res.send('Node.js backend is running and connected to Supabase!');
});

// ==========================
// USER AUTHENTICATION ROUTES
// ==========================

// REGISTER ROUTE
app.post('/register', async (req, res) => {
  const { first_name, middle_name, last_name, username, password } = req.body;

  if (!first_name || !last_name || !username || !password) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  try {
    const checkResult = await db.query('SELECT username FROM users WHERE username = $1', [username]);
    if (checkResult.rows.length > 0) {
      return res.status(409).json({ success: false, message: 'Username taken' });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await db.query(
      `INSERT INTO users (first_name, middle_name, last_name, username, password_hash, role, is_active)
       VALUES ($1, $2, $3, $4, $5, 'Staff', TRUE)`,
      [first_name, middle_name, last_name, username, hashedPassword]
    );

    res.status(201).json({ success: true, message: 'Account created' });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// LOGIN ROUTE
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required' });
  }

  try {
    const result = await db.query('SELECT * FROM users WHERE username = $1 AND is_active = TRUE', [username]);

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid username or password' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (isMatch) {
      await db.query('UPDATE users SET last_login = NOW() WHERE user_id = $1', [user.user_id]);

      const fullName = [user.first_name, user.middle_name, user.last_name]
        .filter(part => part && part.trim().length > 0)
        .join(' ');

      res.json({
        success: true,
        message: 'Login successful',
        user: {
          user_id: user.user_id,
          username: user.username,
          full_name: fullName,
          role: user.role
        }
      });
    } else {
      res.status(401).json({ success: false, message: 'Invalid username or password' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// UPDATE USER ACCOUNT (self-service)
app.put('/update-account/:userId', async (req, res) => {
  const { userId } = req.params;
  const { full_name, username, current_password, new_password } = req.body;

  if (!userId) {
    return res.status(400).json({ success: false, message: 'User ID is required' });
  }

  try {
    const nameParts = (full_name || '').trim().split(/\s+/);
    let first_name = '', middle_name = '', last_name = '';

    if (nameParts.length === 1) {
      first_name = last_name = nameParts[0];
    } else if (nameParts.length === 2) {
      first_name = nameParts[0];
      last_name = nameParts[1];
    } else if (nameParts.length >= 3) {
      first_name = nameParts[0];
      middle_name = nameParts.slice(1, -1).join(' ');
      last_name = nameParts[nameParts.length - 1];
    }

    const userResult = await db.query('SELECT * FROM users WHERE user_id = $1', [userId]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const user = userResult.rows[0];

    if (current_password && new_password) {
      const isMatch = await bcrypt.compare(current_password, user.password_hash);
      if (!isMatch) {
        return res.status(401).json({ success: false, message: 'Current password is incorrect' });
      }

      const hashedNewPassword = await bcrypt.hash(new_password, saltRounds);
      await db.query(
        `UPDATE users SET first_name=$1, middle_name=$2, last_name=$3, username=$4, password_hash=$5 WHERE user_id=$6`,
        [first_name, middle_name, last_name, username, hashedNewPassword, userId]
      );
    } else {
      await db.query(
        `UPDATE users SET first_name=$1, middle_name=$2, last_name=$3, username=$4 WHERE user_id=$5`,
        [first_name, middle_name, last_name, username, userId]
      );
    }

    res.json({ success: true, message: 'Account updated successfully', user: { user_id: userId, username, full_name } });
  } catch (error) {
    console.error('Update account error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ==========================
// USER MANAGEMENT ROUTES (Admin Only)
// ==========================

// GET ALL USERS
app.get('/get-users', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT
        user_id AS id,
        TRIM(CONCAT_WS(' ',
          first_name,
          NULLIF(TRIM(COALESCE(middle_name, '')), ''),
          last_name
        )) AS full_name,
        username,
        role,
        is_active,
        created_at,
        last_login
      FROM users
      ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// ADMIN UPDATE USER
app.put('/admin-update-user/:userId', async (req, res) => {
  const { userId } = req.params;
  const { full_name, username, role } = req.body;

  if (!userId) return res.status(400).json({ success: false, message: 'User ID is required' });

  const allowedRoles = ['Admin', 'Staff'];
  if (role && !allowedRoles.includes(role)) {
    return res.status(400).json({ success: false, message: 'Invalid role. Must be Admin or Staff.' });
  }

  try {
    const nameParts = (full_name || '').trim().split(/\s+/);
    let first_name = '', middle_name = '', last_name = '';

    if (nameParts.length === 1) {
      first_name = last_name = nameParts[0];
    } else if (nameParts.length === 2) {
      first_name = nameParts[0];
      last_name = nameParts[1];
    } else if (nameParts.length >= 3) {
      first_name = nameParts[0];
      middle_name = nameParts.slice(1, -1).join(' ');
      last_name = nameParts[nameParts.length - 1];
    }

    const checkResult = await db.query(
      'SELECT user_id FROM users WHERE username = $1 AND user_id != $2',
      [username, userId]
    );

    if (checkResult.rows.length > 0) {
      return res.status(409).json({ success: false, message: 'Username is already taken by another user' });
    }

    await db.query(
      `UPDATE users SET first_name=$1, middle_name=$2, last_name=$3, username=$4, role=$5 WHERE user_id=$6`,
      [first_name, middle_name, last_name, username, role, userId]
    );

    res.json({ success: true, message: 'User updated successfully' });
  } catch (error) {
    console.error('Admin update user error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// DELETE USER
app.delete('/delete-user/:userId', async (req, res) => {
  const { userId } = req.params;

  if (!userId) return res.status(400).json({ success: false, message: 'User ID is required' });

  try {
    const result = await db.query('DELETE FROM users WHERE user_id = $1', [userId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({ success: true, message: 'User deleted successfully' });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ success: false, message: 'Delete failed' });
  }
});

// ==========================
// ASSISTANCE REQUEST ROUTES
// ==========================

// INSERT ASSISTANCE REQUEST
app.post('/create-assistance', async (req, res) => {
  const assistance = req.body;

  try {
    const result = await db.query(`
      INSERT INTO assistance_requests
      (last_name, first_name, block_lot, subdivision_street, barangay, city, province,
       complete_address, contact_number, amount, grants, assistance_type, is_completed,
       name_of_organization, date_of_event, venue_of_event, request)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
      RETURNING id
    `, [
      assistance.last_name,
      assistance.first_name,
      assistance.blockLot           || '',
      assistance.subdivision         || '',
      assistance.barangay            || '',
      assistance.city                || '',
      assistance.province            || '',
      assistance.address,
      assistance.contactNumber,
      assistance.amount              || null,
      assistance.grants              || null,
      assistance.assistanceType,
      assistance.isCompleted ? true : false,
      assistance.nameOfOrganization  || null,
      assistance.dateOfEvent         || null,
      assistance.venueOfEvent        || null,
      assistance.request             || null,
    ]);

    res.json({ success: true, id: result.rows[0].id });
  } catch (err) {
    console.error('Insert assistance error:', err);
    res.status(500).json({ success: false, message: 'Database error', error: err.message });
  }
});

// FETCH ALL REQUESTS
app.get('/get-assistances', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM assistance_requests ORDER BY id DESC');

    const formattedResults = result.rows.map(row => ({
      id:                 row.id.toString(),
      first_name:         row.first_name,
      last_name:          row.last_name,
      address:            row.complete_address,
      contactNumber:      row.contact_number,
      assistanceType:     row.assistance_type,
      isCompleted:        row.is_completed === true,
      nameOfOrganization: row.name_of_organization,
      dateOfEvent:        row.date_of_event,
      venueOfEvent:       row.venue_of_event,
      request:            row.request,
      amount:             row.amount,
      grants:             row.grants,
      createdAt:          row.created_at,
      updatedAt:          row.updated_at,
    }));

    res.json(formattedResults);
  } catch (err) {
    console.error('Fetch assistances error:', err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// UPDATE AN EXISTING REQUEST
app.put('/update-assistance/:id', async (req, res) => {
  const { id } = req.params;
  const data = req.body;
  const formattedDate = data.dateOfEvent ? data.dateOfEvent.split('T')[0] : null;

  try {
    await db.query(`
      UPDATE assistance_requests
      SET
        last_name            = $1,
        first_name           = $2,
        complete_address     = $3,
        contact_number       = $4,
        amount               = $5,
        grants               = $6,
        assistance_type      = $7,
        is_completed         = $8,
        name_of_organization = $9,
        date_of_event        = $10,
        venue_of_event       = $11,
        request              = $12
      WHERE id = $13
    `, [
      data.last_name,
      data.first_name,
      data.address,
      data.contactNumber,
      data.amount              || null,
      data.grants              || null,
      data.assistanceType,
      data.isCompleted ? true : false,
      data.nameOfOrganization  || null,
      formattedDate,
      data.venueOfEvent        || null,
      data.request             || null,
      id,
    ]);

    res.json({ success: true, message: 'Updated successfully' });
  } catch (err) {
    console.error('Update assistance error:', err);
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

// DELETE A REQUEST
app.delete('/delete-assistance/:id', async (req, res) => {
  const { id } = req.params;

  try {
    await db.query('DELETE FROM assistance_requests WHERE id = $1', [id]);
    res.json({ success: true, message: 'Deleted successfully' });
  } catch (err) {
    console.error('Delete assistance error:', err);
    res.status(500).json({ success: false, message: 'Delete failed' });
  }
});

// ==========================
// ATTACHMENT ROUTES
// ==========================

// UPLOAD MULTIPLE FILES
app.post('/upload-attachments/:id', upload.array('files', 10), async (req, res) => {
  const assistanceId = req.params.id;

  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ success: false, message: 'No files uploaded' });
  }

  try {
    for (const file of req.files) {
      await db.query(
        'INSERT INTO assistance_attachments (assistance_id, file_name, file_url, file_type) VALUES ($1, $2, $3, $4)',
        [assistanceId, file.originalname, `/uploads/${file.filename}`, file.mimetype]
      );
    }

    res.json({ success: true, count: req.files.length });
  } catch (err) {
    console.error('Attachment insert error:', err);
    res.status(500).json({ success: false, message: 'Failed to save attachments' });
  }
});

// GET ALL ATTACHMENTS for a request
app.get('/get-attachments/:id', async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM assistance_attachments WHERE assistance_id = $1 ORDER BY uploaded_at ASC',
      [req.params.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch attachments error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch attachments' });
  }
});

// DELETE A SINGLE ATTACHMENT
app.delete('/delete-attachment/:id', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM assistance_attachments WHERE id = $1', [req.params.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Attachment not found' });
    }

    const filePath = path.join(__dirname, result.rows[0].file_url);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    await db.query('DELETE FROM assistance_attachments WHERE id = $1', [req.params.id]);
    res.json({ success: true, message: 'Attachment deleted' });
  } catch (err) {
    console.error('Delete attachment error:', err);
    res.status(500).json({ success: false, message: 'Failed to delete attachment' });
  }
});

// Multer error handler
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || err.message) {
    return res.status(400).json({ success: false, message: err.message });
  }
  next(err);
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Server is running on port ${port}`);
});
