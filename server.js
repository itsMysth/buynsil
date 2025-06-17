const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const fs = require('fs');
const session = require('express-session');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const app = express();
require('dotenv').config();

app.use(express.urlencoded({ extended: true }));
const db = mysql.createConnection({
    host: process.env.MYSQL_HOST,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASS,
    database: process.env.MYSQL_DB,
  });
 
  db.connect((err) => {
    if (err) {
      console.error('Error connecting to the database:', err);
    } else {
      console.log('Connected to MySQL database :D');
    }
  });

function ensureAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  } else {
    res.redirect('/login'); 
  }
}

app.use(
  session({
    secret: 'your-secret-key', 
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } 
  })
);

const uploadPath = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadPath)) {
  fs.mkdirSync(uploadPath, { recursive: true });
}

app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

app.get('/admin/reports', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'Admin_reports.html'));
});

app.get('/admin/listings', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'Admin_listings.html'));
});

app.get('/admin/users', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'Admin_users.html'));
});

app.get('/addlisting', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'addlisting.html'));
});

app.get('/messages', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'message.html'));
});

app.get('/messages/:seller_id', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'message.html'));
});

app.get('/success', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'success.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.get('/useritems', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'useritems.html'));
});

app.get('/homepage', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'homepage.html'));
});

app.get('/saveditems', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'saveditems.html'));
});

app.get('/profile', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'profile.html'));
});

app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

app.get('/api/user/items', (req, res) => {
  const userId = req.query.userId;
  const search = req.query.search?.trim();

  if (!userId) {
    return res.status(400).json({ error: 'User ID is required' });
  }

  let query = 'SELECT * FROM listings WHERE seller_id = ?';
  const params = [userId];

  if (search) {
    query += ' AND item_name LIKE ?';
    params.push(`%${search}%`);
  }

  db.execute(query, params, (err, results) => {
    if (err) {
      console.error('Database query error:', err);
      return res.status(500).json({ error: 'Database query failed' });
    }

    res.json(results);
  });
});


app.get('/api/currentUser', (req, res) => {
  if (req.session.user) {
    res.json({ user: req.session.user });
  } else {
    res.json({ user: null });
  }
});

app.get('/get-session-data', (req, res) => {
  if (req.session.user) {
    res.json(req.session.user);
  } else {
    res.status(401).send('Unauthorized');
  }
});

app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'public', 'uploads')); // Store in public/uploads
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Use a timestamp for unique filenames
  }
});

const upload = multer({ storage: storage });

app.post('/additem', upload.single('image'), (req, res) => {
  // Check if file is uploaded
  console.log('File uploaded:', req.file); 

  const { item_name, price, category, seccategory, description } = req.body;
  const seller_id = req.session.user.id; // Get the user ID from the session
  
  // Get the image path if available, otherwise null
  const image = req.file ? `/uploads/${req.file.filename}` : null;
  
  // SQL query to insert new listing into the database
  const sql = 'INSERT INTO listings (seller_id, item_name, price, category, seccategory, description, image, status) VALUES (?, ?, ?, ?, ?, ?, ?, "Active")';
  
  db.query(sql, [seller_id, item_name, price, category, seccategory, description, image], (err, result) => {
    if (err) {
      console.error('Error while adding item:', err);
      return res.send('Error while adding listing');
    }
    
    // Redirect to homepage or another page after successful insertion
    res.redirect('/homepage');
  });
});

app.use(express.json());

app.post('/items/:id', (req, res) => {
  const { id } = req.params;
  const { item_name, price, category, seccategory, status, description } = req.body;

  // Define the SQL query for the update
  const sql = `
    UPDATE listings
    SET item_name = ?, price = ?, category = ?, seccategory = ?, status = ?, description = ?
    WHERE item_id = ?
  `;
  // Execute the query with the values
  db.query(sql, [item_name, price, category, seccategory, status, description, id], (err, result) => {
    if (err) {
      console.error('Error updating item:', err);
      return res.status(500).send('Internal server error.');
    }

    // Check if any rows were affected
    if (result.affectedRows === 0) {
      return res.status(404).send('Item not found.');
    }

    // Redirect after successful update
    res.redirect('/useritems');
  });
});

app.post('/chat/send', upload.single('image'), async (req, res) => {
  const senderId = req.session.user.id;
  const { receiverId, content } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;

  if (!senderId || !receiverId || (!content && !image)) {
    return res.status(400).json({ error: 'Missing data' });
  }

  const fullContent = content || '';
  const combined = image ? `${fullContent}\n<img src="${image}" class="max-w-xs rounded mt-2" />` : fullContent;

  await db.query(
    'INSERT INTO messages (sender_id, receiver_id, content, timestamp) VALUES (?, ?, ?, NOW())',
    [senderId, receiverId, combined]
  );

  res.status(200).json({ success: true });
});


app.get('/api/messages/unread', async (req, res) => {
  const userId = req.session.user.id;
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const [rows] = await db.promise().query(
      `SELECT COUNT(*) AS unread_count FROM messages WHERE receiver_id = ? AND is_read = FALSE`,
      [userId]
    );
    res.json({ unread: rows[0].unread_count > 0 });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to check unread messages' });
  }
});

app.get('/chat/messages', async (req, res) => {
  const senderId = req.session.user.id;
  const receiverId = req.query.receiverId;

  if (!senderId) return res.status(401).json({ error: 'Unauthorized' });
  if (!receiverId) return res.status(400).json({ error: 'receiverId is required' });

  try {
    // Mark unread messages as read
    await db.promise().query(
      `UPDATE messages 
       SET is_read = TRUE 
       WHERE sender_id = ? AND receiver_id = ? AND is_read = FALSE`,
      [receiverId, senderId]
    );

    // Fetch conversation
    const [rows] = await db.promise().query(
      `SELECT *, ? AS current_user_id 
       FROM messages 
       WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
       ORDER BY timestamp ASC`,
      [senderId, senderId, receiverId, receiverId, senderId]
    );

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.get('/api/messages', (req, res) => {
  const userId = req.session.user.id;
  if (!userId) return res.status(401).json({ error: 'Not logged in' });

  const query = `
    SELECT 
      u.id AS user_id,
      u.name,
      u.profilepic,
      m.content AS last_message,
      m.timestamp AS last_timestamp,
      m.sender_id,
      m.receiver_id,
      (m.receiver_id = ? AND m.is_read = FALSE) AS is_unread
    FROM messages m
    JOIN users u ON 
      u.id = IF(m.sender_id = ?, m.receiver_id, m.sender_id)
    JOIN (
      SELECT 
        LEAST(sender_id, receiver_id) AS user_a,
        GREATEST(sender_id, receiver_id) AS user_b,
        MAX(timestamp) AS max_time
      FROM messages
      WHERE sender_id = ? OR receiver_id = ?
      GROUP BY user_a, user_b
    ) lm ON 
      LEAST(m.sender_id, m.receiver_id) = lm.user_a AND 
      GREATEST(m.sender_id, m.receiver_id) = lm.user_b AND 
      m.timestamp = lm.max_time
    ORDER BY m.timestamp DESC
  `;

  db.query(query, [userId, userId, userId, userId], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.get('/api/search-users', (req, res) => {
  const currentUserId = req.session.user.id;
  const searchTerm = req.query.query || '';

  if (!currentUserId) return res.status(401).json({ error: 'Not logged in' });

  const query = `
    SELECT
      u.id AS user_id,
      u.name,
      u.profilepic,
      m.content AS last_message,
      m.timestamp AS last_timestamp,
      m.sender_id,
      m.receiver_id,
      CASE
        WHEN m.is_read = FALSE AND m.receiver_id = ? THEN TRUE
        ELSE FALSE
      END AS is_unread
    FROM users u
    LEFT JOIN messages m ON (
      (m.sender_id = u.id OR m.receiver_id = u.id)
      AND m.timestamp = (
        SELECT MAX(m2.timestamp)
        FROM messages m2
        WHERE
          ((m2.sender_id = u.id AND m2.receiver_id = ?) OR (m2.sender_id = ? AND m2.receiver_id = u.id))
      )
    )
    WHERE u.name LIKE CONCAT('%', ?, '%')
      AND u.id != ?
    ORDER BY COALESCE(m.timestamp, '1970-01-01') DESC
    LIMIT 50
  `;

  db.query(query, [currentUserId, currentUserId, currentUserId, searchTerm, currentUserId], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.get('/api/products', (req, res) => {
    const { search, category, subcategory, sort } = req.query;
    const currentUserId = req.session.user.id;


    let query = `
        SELECT listings.*, users.name AS seller_name 
        FROM listings 
        JOIN users ON listings.seller_id = users.id 
        WHERE listings.status != 'Sold' AND listings.status != 'Banned' AND listings.seller_id != ?
    `;
    const params = [currentUserId];

    if (search) {
        query += ` AND listings.item_name LIKE ?`;
        params.push(`%${search}%`);
    }

    if (category && category !== 'All') {
        if (category === 'General') {
            query += ` AND (listings.category IS NULL OR listings.category = '')`;
        } else {
            query += ` AND listings.category = ?`;
            params.push(category);
        }
    }

    if (subcategory && subcategory !== 'All' && subcategory !== 'Select Subcategory') {
        query += ` AND listings.seccategory = ?`;
        params.push(subcategory);
    }

    switch (sort) {
        case 'price-low':
            query += ` ORDER BY listings.price ASC`;
            break;
        case 'price-high':
            query += ` ORDER BY listings.price DESC`;
            break;
        case 'name':
            query += ` ORDER BY listings.item_name ASC`;
            break;
        case 'newest':
            query += ` ORDER BY listings.dateAdded DESC`;
            break;
        case 'old':
            query += ` ORDER BY listings.dateAdded ASC`;
            break;
        default:
            query += ` ORDER BY listings.dateAdded DESC`;
    }

    db.query(query, params, (err, results) => {
        if (err) {
            console.error('Query error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(results);
    });
});

app.get('/api/seller/:id', (req, res) => {
  const userId = req.params.id;

  const sql = `
    SELECT users.name, userinfo.city, userinfo.province, userinfo.bio, users.profilepic
    FROM users
    LEFT JOIN userinfo ON users.id = userinfo.userId
    WHERE users.id = ?`;
  
  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Database error' });
    }
    
    // If no data found, just send null or empty object
    if (results.length === 0) {
      return res.json(null);
    }

    // Just send the first row object directly
    res.json(results[0]);
  });
});


app.delete('/api/user/items/:itemId', (req, res) => {
  const itemId = req.params.itemId;

  if (!itemId) {
    return res.status(400).json({ error: 'Item ID is required' });
  }

  const deleteQuery = 'DELETE FROM listings WHERE item_id = ?';

  db.execute(deleteQuery, [itemId], (err, result) => {
    if (err) {
      console.error('Database deletion error:', err);
      return res.status(500).json({ error: 'Failed to delete item' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Item not found' });
    }

    res.json({ message: 'Item deleted successfully' });
  });
});

app.get('/api/user-listings', ensureAuthenticated, (req, res) => {
  const userId = req.session.user.id;  // Get the logged-in user's ID from the session

  // SQL query to get all listings by this user
  const sql = 'SELECT * FROM listings WHERE seller_id = ?';

  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching user listings:', err);
      return res.status(500).json({ error: 'Failed to fetch listings' });
    }
    res.json(results);  // Send the listings back as a JSON response
  });
});


app.get('/api/user-listings-count', ensureAuthenticated, (req, res) => {
  const userId = req.session.user.id; // Get the logged-in user's ID

  // Query to count how many listings the user has
  const countSql = 'SELECT COUNT(*) AS totalListings FROM listings WHERE seller_id = ?';

  db.query(countSql, [userId], (err, countResult) => {
    if (err) {
      console.error('Error counting listings:', err);
      return res.status(500).json({ error: 'Failed to count listings' });
    }

    const totalListings = countResult[0].totalListings; // Get the count from the result
    res.json({ totalListings }); // Return just the count
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.send('❌ Failed to log out.');
    }
    res.redirect('/'); // Or wherever you want after logout
  });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const sql = 'SELECT * FROM users WHERE email = ?';
  
  db.query(sql, [email], async (err, results) => {
    if (err) {
      console.error(err);
      return res.redirect('/login?error=server');
    }

    if (results.length === 0) {
      return res.redirect('/login?error=invalid');
    }

    const user = results[0];

    if (user.status === 'Banned') {
      const reason = encodeURIComponent(user.banReason || 'You have been banned from the platform.');
      return res.redirect(`/login?error=banned&reason=${reason}`);
    }

    if (user.verified !== 1) {
      return res.redirect('/login?error=unverified');
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.redirect('/login?error=invalid');
    }

    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      status: user.status
    };

    console.log('Session after login:', req.session.user);

    return res.redirect(user.status === 'Admin' ? '/admin' : '/homepage');
  });
});



const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASS,
  }
});

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  const saltRounds = 10;

  // Check if email exists
  const checkEmailSql = 'SELECT * FROM users WHERE email = ?';
  db.query(checkEmailSql, [email], async (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: '❌ Error checking email.' });
    }

    if (results.length > 0) {
      // Email exists
      return res.status(400).json({ success: false, message: 'Email already registered.' });
    }

    try {
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // Create token for email verification
      const verificationToken = crypto.randomBytes(32).toString('hex');

      // Insert user with token and verified=false
      const insertSql = `INSERT INTO users (name, email, password, verified, verification_token, status) VALUES (?, ?, ?, 0, ?, 'Unverified')`;
      db.query(insertSql, [name, email, hashedPassword, verificationToken], async (err, result) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ success: false, message: '❌ Failed to register.' });
        }

        // Send verification email
        const verifyUrl = `http://localhost:3000/verify?token=${verificationToken}`;  // Update domain for production

        const mailOptions = {
          from: '"Baynsil" <oniljauculan@gmail.com>',
          to: email,
          subject: 'Please verify your email',
          html: `<p>Hi ${name},</p>
                 <p>Thanks for registering! Please click the link below to verify your email address:</p>
                 <a href="${verifyUrl}">${verifyUrl}</a>`
        };

        try {
          await transporter.sendMail(mailOptions);
          return res.json({ success: true, message: 'Registration successful! Please check your email to verify your account.' });
        } catch (emailErr) {
          console.error('Error sending verification email:', emailErr);
          return res.status(500).json({ success: false, message: 'Failed to send verification email.' });
        }
      });

    } catch (error) {
      console.error(error);
      res.status(500).json({ success: false, message: '❌ Error hashing password.' });
    }
  });
});

app.post('/api/change-password', async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.session.user.id; // Adjust if using sessions or JWT

  if (!userId) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  // Get the current hashed password from DB
  const sql = 'SELECT password FROM users WHERE id = ?';
  db.query(sql, [userId], async (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: 'Server error.' });
    }

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    const storedHash = results[0].password;
    const isMatch = await bcrypt.compare(currentPassword, storedHash);

    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Incorrect current password.' });
    }

    const newHash = await bcrypt.hash(newPassword, 10);

    const updateSql = 'UPDATE users SET password = ? WHERE id = ?';
    db.query(updateSql, [newHash, userId], (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: 'Failed to update password.' });
      }

      return res.json({ success: true, message: 'Password updated successfully.' });
    });
  });
});

app.post('/api/update-address', (req, res) => {
  const { city, state } = req.body;
  const userId = req.session.user.id;

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  // Check if userinfo exists for this user
  const checkSql = 'SELECT * FROM userinfo WHERE userId = ?';
  db.query(checkSql, [userId], (err, results) => {
    if (err) {
      console.error('Error checking userinfo:', err);
      return res.status(500).json({ message: 'Server error' });
    }

    if (results.length > 0) {
      // User info exists, perform UPDATE
      const updateSql = `
        UPDATE userinfo 
        SET city = ?, province = ?
        WHERE userId = ?`;
      db.query(updateSql, [city, state, userId], (err) => {
        if (err) {
          console.error('Update error:', err);
          return res.status(500).json({ message: 'Failed to update address' });
        }
        return res.json({ message: 'Address updated successfully' });
      });
    } else {
      // No user info, perform INSERT
      const insertSql = `
        INSERT INTO userinfo (userId, city, province)
        VALUES (?, ?, ?)`;
      db.query(insertSql, [userId, city, state], (err) => {
        if (err) {
          console.error('Insert error:', err);
          return res.status(500).json({ message: 'Failed to save address' });
        }
        return res.json({ message: 'Address saved successfully' });
      });
    }
  });
});

app.get('/api/seller/:id', (req, res) => {
  const userId = req.params.id;

  const sql = `
    SELECT users.name, userinfo.city, userinfo.province, userinfo.bio, users.profilepic
    FROM users
    LEFT JOIN userinfo ON users.id = userinfo.userId
    WHERE users.id = ?`;
  
  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Database error' });
    }
    
    // If no data found, just send null or empty object
    if (results.length === 0) {
      return res.json(null);
    }

    // Just send the first row object directly
    res.json(results[0]);
  });
});

app.post('/api/update-bio', (req, res) => {
  const { bio } = req.body;
  const userId = req.session.user.id;

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const checkSql = 'SELECT * FROM userinfo WHERE userId = ?';
  db.query(checkSql, [userId], (err, results) => {
    if (err) {
      console.error('Check bio error:', err);
      return res.status(500).json({ message: 'Server error' });
    }

    if (results.length > 0) {
      const updateSql = 'UPDATE userinfo SET bio = ? WHERE userId = ?';
      db.query(updateSql, [bio, userId], (err) => {
        if (err) {
          console.error('Update bio error:', err);
          return res.status(500).json({ message: 'Failed to update bio' });
        }
        return res.json({ message: 'Bio updated successfully' });
      });
    } else {
      const insertSql = 'INSERT INTO userinfo (userId, bio) VALUES (?, ?)';
      db.query(insertSql, [userId, bio], (err) => {
        if (err) {
          console.error('Insert bio error:', err);
          return res.status(500).json({ message: 'Failed to save bio' });
        }
        return res.json({ message: 'Bio saved successfully' });
      });
    }
  });
});

app.get('/api/get-userinfo', (req, res) => {
  const userId = req.session.user.id;

  if (!userId) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }

  const sql = 'SELECT * FROM userinfo WHERE userId = ?';
  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error('DB error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    if (results.length === 0) {
      // No record found - you can return empty or default values
      return res.json({ success: true, data: null });
    }

    // Send back the first (and presumably only) row for the user
    return res.json({ success: true, data: results[0] });
  });
});

app.get('/verify', (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).send('Verification token is missing.');
  }

  const sql = `
    UPDATE users 
    SET verified = 1, status = 'Active', verification_token = NULL 
    WHERE verification_token = ?
  `;

  db.query(sql, [token], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Database error during verification.');
    }

    if (result.affectedRows === 0) {
      return res.status(400).send('Invalid or expired verification token.');
    }

    res.send('Email verified successfully! You can now log in.');
  });
});


// Save item
app.post('/api/saved-items/:item_id', (req, res) => {
    const userId = req.session.user.id;
    const itemId = req.params.item_id;

    const sql = `
      INSERT INTO saveditems (user_id, item_id, saved_at)
      VALUES (?, ?, NOW())
      ON DUPLICATE KEY UPDATE saved_at = NOW()
    `;

    db.query(sql, [userId, itemId], (err) => {
        if (err) return res.status(500).json({ error: 'Save failed' });
        res.sendStatus(200);
    });
});

app.get('/api/saved-items/user', (req, res) => {
  const userId = req.session.user.id;

  // SQL query: get all saved item details for the user
  const query = `
    SELECT 
      l.item_id,
      l.seller_id,
      l.item_name,
      l.price,
      l.image,
      l.category,
      l.seccategory,
      l.description,
      l.status,
      l.dateAdded,
      s.saved_at,
      u.name AS seller_name
    FROM saveditems s
    JOIN listings l ON s.item_id = l.item_id
    JOIN users u ON l.seller_id = u.id
    WHERE s.user_id = ?
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching saved items:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    // results is an array of saved items with listing details
    res.json(results);
  });
});

app.get('/api/saved-items/user/sort', (req, res) => {
  const userId = req.session.user.id;
  const sortBy = req.query.by || 'recent';

  // Define sort clause based on sortBy param
  let sortClause = '';
  switch (sortBy) {
    case 'price-low':
      sortClause = 'ORDER BY l.price ASC';
      break;
    case 'price-high':
      sortClause = 'ORDER BY l.price DESC';
      break;
    case 'newest':
      sortClause = 'ORDER BY l.dateAdded DESC';
      break;
    case 'recent':
    default:
      sortClause = 'ORDER BY s.saved_at DESC';
      break;
  }

  const query = `
    SELECT 
      l.item_id,
      l.seller_id,
      l.item_name,
      l.price,
      l.image,
      l.category,
      l.seccategory,
      l.description,
      l.status,
      l.dateAdded,
      s.saved_at,
      u.name AS seller_name
    FROM saveditems s
    JOIN listings l ON s.item_id = l.item_id
    JOIN users u ON l.seller_id = u.id
    WHERE s.user_id = ?
    ${sortClause}
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching sorted saved items:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    res.json(results);
  });
});


app.get('/api/saved-items/user/search', (req, res) => {
  const userId = req.session.user.id;
  if (!userId) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  const searchTerm = req.query.term || '';
  const searchPattern = `%${searchTerm}%`;

  const query = `
    SELECT 
      l.item_id,
      l.seller_id,
      l.item_name,
      l.price,
      l.image,
      l.category,
      l.seccategory,
      l.description,
      l.status,
      l.dateAdded,
      s.saved_at,
      u.name AS seller_name
    FROM saveditems s
    JOIN listings l ON s.item_id = l.item_id
    JOIN users u ON l.seller_id = u.id
    WHERE s.user_id = ?
      AND (
        l.item_name LIKE ?
        OR l.category LIKE ?
        OR l.seccategory LIKE ?
        OR l.description LIKE ?
      )
    ORDER BY s.saved_at DESC
  `;

  db.query(query, [userId, searchPattern, searchPattern, searchPattern, searchPattern], (err, results) => {
    if (err) {
      console.error('Error fetching saved items with search:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    console.log(results);
    res.json(results);
  });
});


// Unsave item
app.delete('/api/saved-items/:item_id', (req, res) => {
    const userId = req.session.user.id;
    const itemId = req.params.item_id;

    db.query(
        'DELETE FROM saveditems WHERE user_id = ? AND item_id = ?',
        [userId, itemId],
        (err) => {
            if (err) return res.status(500).json({ error: 'Delete failed' });
            res.sendStatus(200);
        }
    );
});

// Get all saved item IDs for the user
app.get('/api/saved-items', (req, res) => {
    const userId = req.session.user.id;

    db.query(
        'SELECT item_id FROM saveditems WHERE user_id = ?',
        [userId],
        (err, results) => {
            if (err) return res.status(500).json({ error: 'Fetch failed' });
            res.json(results.map(r => r.item_id));
        }
    );
});

app.get('/profile-pic', (req, res) => {
  const userId = req.session.user.id;

  db.query('SELECT profilepic FROM users WHERE id = ?', [userId], (err, results) => {
    if (err) return res.status(500).send('Database error');
    if (results.length === 0) return res.status(404).send('User not found');

    const filename = results[0].profilepic || 'defaultprofile.webp';
    const imagePath = path.join(__dirname, 'public/uploads', filename);

    res.sendFile(imagePath);
  });
});

app.post('/upload-profile-pic', upload.single('profilepic'), (req, res) => {
  const userId = req.session.user.id;
  const filename = req.file.filename;

  db.query('UPDATE users SET profilepic = ? WHERE id = ?', [filename, userId], (err) => {
    if (err) return res.status(500).send('Database update failed');
    res.sendStatus(200);
  });
});

app.get('/api/admin/stats', (req, res) => {
  const stats = {};

  // Query 1: Total Verified Users
  db.query('SELECT COUNT(*) AS totalUsers FROM users WHERE verified = 1', (err, result) => {
    if (err) {
      console.error('Error fetching total users:', err);
      return res.status(500).json({ error: 'Error fetching total users' });
    }
    stats.totalUsers = result[0].totalUsers;

    // Query 2: Total Listings
    db.query('SELECT COUNT(*) AS totalListings FROM listings', (err, result) => {
      if (err) {
        console.error('Error fetching total listings:', err);
        return res.status(500).json({ error: 'Error fetching total listings' });
      }
      stats.totalListings = result[0].totalListings;

      // Query 3: Active Listings
      db.query("SELECT COUNT(*) AS activeListings FROM listings WHERE status = 'Active'", (err, result) => {
        if (err) {
          console.error('Error fetching active listings:', err);
          return res.status(500).json({ error: 'Error fetching active listings' });
        }
        stats.activeListings = result[0].activeListings;

        // Query 4: Pending Reports
        db.query("SELECT COUNT(*) AS pendingReports FROM reports WHERE status = 'Pending'", (err, result) => {
          if (err) {
            console.error('Error fetching pending reports:', err);
            return res.status(500).json({ error: 'Error fetching pending reports' });
          }
          stats.pendingReports = result[0].pendingReports;

          // Query 5: Resolved Today
          db.query("SELECT COUNT(*) AS resolvedToday FROM reports WHERE status = 'Resolved' AND date = CURDATE()", (err, result) => {
            if (err) {
              console.error('Error fetching resolved reports:', err);
              return res.status(500).json({ error: 'Error fetching resolved reports' });
            }
            stats.resolvedToday = result[0].resolvedToday;

            // Final response
            res.json(stats);
          });
        });
      });
    });
  });
});

app.get('/api/admin/users/recent', (req, res) => {
  const sql = `
    SELECT id, name, profilepic, joinDate 
    FROM users 
    WHERE verified = 1 
    ORDER BY joinDate DESC 
    LIMIT 3
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error('Error fetching recent users:', err);
      return res.status(500).json({ error: 'Failed to load recent users' });
    }

    res.json(results);
  });
});

app.get('/api/admin/listings/recent', (req, res) => {
  const sql = `
    SELECT item_id AS id, item_name AS name, price, image, category 
    FROM listings 
    ORDER BY dateAdded DESC 
    LIMIT 3
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error('Error fetching recent listings:', err);
      return res.status(500).json({ error: 'Failed to load listings' });
    }

    res.json(results);
  });
});

app.get('/api/admin/users', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const perPage = parseInt(req.query.perPage) || 10;
  const offset = (page - 1) * perPage;

  const search = req.query.search || '';
  const status = req.query.status || 'all';
  const sort = req.query.sort || 'newest';

  // Base WHERE clause excluding Admins
  let whereClause = `WHERE (u.name LIKE ? OR u.email LIKE ?) AND (u.status IS NULL OR u.status != 'Admin')`;
  let params = [`%${search}%`, `%${search}%`];

  // Apply filters
  if (status === 'active') {
    whereClause += ` AND u.verified = 1 AND (u.status IS NULL OR u.status != 'Banned')`;
  } else if (status === 'unverified') {
    whereClause += ` AND u.verified = 0`;
  } else if (status === 'banned') {
    whereClause += ` AND u.status = 'Banned'`;
  }

  // Sorting logic
  let sortColumn = 'u.joinDate';
  let sortOrder = 'DESC';

  if (sort === 'oldest') {
    sortColumn = 'u.joinDate';
    sortOrder = 'ASC';
  } else if (sort === 'name-asc') {
    sortColumn = 'u.name';
    sortOrder = 'ASC';
  } else if (sort === 'name-desc') {
    sortColumn = 'u.name';
    sortOrder = 'DESC';
  }

  const sql = `
    SELECT 
      u.id AS _id,
      u.name,
      u.email,
      u.profilepic AS profilePic,
      u.verified,
      u.status,
      u.joinDate AS createdAt,
      COUNT(l.item_id) AS listingCount
    FROM users u
    LEFT JOIN listings l ON u.id = l.seller_id
    ${whereClause}
    GROUP BY u.id
    ORDER BY ${sortColumn} ${sortOrder}
    LIMIT ? OFFSET ?
  `;

  const countSql = `
    SELECT COUNT(*) AS total FROM users u
    ${whereClause}
  `;

  db.query(countSql, params, (countErr, countResults) => {
    if (countErr) {
      console.error('Count error:', countErr);
      return res.status(500).json({ error: 'Failed to count users' });
    }

    db.query(sql, [...params, perPage, offset], (err, results) => {
      if (err) {
        console.error('Error fetching users:', err);
        return res.status(500).json({ error: 'Failed to fetch users' });
      }

      const users = results.map(user => {
        let userStatus = 'Unverified';
        if (user.status === 'Banned') {
          userStatus = 'Banned';
        } else if (user.verified === 1) {
          userStatus = 'Active';
        }

        return {
          ...user,
          isBanned: userStatus === 'Banned',
          status: userStatus
        };
      });

      res.json({
        users,
        total: countResults[0].total,
        currentPage: page,
        perPage
      });
    });
  });
});

app.post('/api/admin/users/:id/ban', (req, res) => {
  const userId = parseInt(req.params.id);
  const { reason } = req.body;

  if (!userId || !reason || reason.trim() === '') {
    return res.status(400).json({ message: 'Invalid user ID or reason' });
  }

  const sql = `UPDATE users SET status = 'Banned', banReason = ? WHERE id = ?`;

  db.query(sql, [reason, userId], (err, result) => {
    if (err) {
      console.error('Error banning user:', err);
      return res.status(500).json({ message: 'Failed to ban user' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'User banned successfully' });
  });
});

app.post('/api/admin/users/:id/unban', (req, res) => {
  const userId = req.params.id;

  const sql = `
    UPDATE users
    SET status = 'Active', banReason = NULL
    WHERE id = ? AND status = 'Banned'
  `;

  db.query(sql, [userId], (err, result) => {
    if (err) {
      console.error('Error unbanning user:', err);
      return res.status(500).json({ message: 'Failed to unban user' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found or not banned' });
    }

    res.json({ message: 'User unbanned successfully' });
  });
});

app.get('/api/admin/listings', (req, res) => {
  const {
    status,
    category,
    subcategory,
    minPrice,
    maxPrice,
    search,
    seller, // <-- NEW
    page = 1
  } = req.query;

  const limit = 10;
  const offset = (page - 1) * limit;

  let filters = [];
  let params = [];

  // Filter: Status
  if (status) {
    filters.push('l.status = ?');
    params.push(status);
  }

  // Filter: Category
  if (category && category !== 'All') {
    filters.push('l.category = ?');
    params.push(category);
  }

  // Filter: Subcategory
  if (subcategory && subcategory !== 'All') {
    filters.push('l.seccategory = ?');
    params.push(subcategory);
  }

  // Filter: Price Range
  if (minPrice) {
    filters.push('l.price >= ?');
    params.push(minPrice);
  }

  if (maxPrice) {
    filters.push('l.price <= ?');
    params.push(maxPrice);
  }

  // Filter: Search by product name
  if (search) {
    filters.push('l.item_name LIKE ?');
    params.push(`%${search}%`);
  }

  // Filter: Seller name
  if (seller) {
    filters.push('u.name LIKE ?');
    params.push(`%${seller}%`);
  }

  const whereClause = filters.length ? `WHERE ${filters.join(' AND ')}` : '';

  const countSql = `SELECT COUNT(*) AS total FROM listings l JOIN users u ON l.seller_id = u.id ${whereClause}`;
  const dataSql = `
    SELECT 
      l.item_id AS id,
      l.item_name AS title,
      l.price,
      l.category,
      l.seccategory,
      l.status,
      l.dateAdded AS createdAt,
      l.image,
      u.id AS userId,
      u.name AS userName,
      u.email AS userEmail,
      u.profilepic AS userProfilePic
    FROM listings l
    JOIN users u ON l.seller_id = u.id
    ${whereClause}
    ORDER BY l.dateAdded DESC
    LIMIT ? OFFSET ?
  `;

  db.query(countSql, params, (err, countResult) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Error counting listings' });
    }

    const total = countResult[0].total;
    const totalPages = Math.ceil(total / limit);

    db.query(dataSql, [...params, limit, offset], (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: 'Error loading listings' });
      }

      const listings = results.map(row => ({
        id: row.id,
        title: row.title,
        price: row.price,
        category: row.category,
        status: row.status,
        createdAt: row.createdAt,
        images: row.image ? [row.image] : [],
        owner: {
          id: row.userId,
          name: row.userName,
          email: row.userEmail,
          profilePic: row.userProfilePic
        }
      }));

      res.json({ listings, total, totalPages });
    });
  });
});

app.get('/api/admin/listings/:id', (req, res) => {
  const listingId = req.params.id;

  const sql = `
    SELECT 
      l.item_id AS id,
      l.item_name AS title,
      l.price,
      l.description,
      l.category,
      l.seccategory AS subcategory,
      l.status,
      l.dateAdded AS createdAt,
      l.image, -- comma-separated string
      u.id AS userId,
      u.name AS userName,
      u.email AS userEmail,
      u.profilepic AS userProfilePic
    FROM listings l
    JOIN users u ON l.seller_id = u.id
    WHERE l.item_id = ?
  `;

  db.query(sql, [listingId], (err, results) => {
    if (err) {
      console.error('Error retrieving listing:', err);
      return res.status(500).json({ message: 'Server error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'Listing not found' });
    }

    const row = results[0];
    const images = row.image ? row.image.split(',').map(i => i.trim()) : [];

    const listing = {
      id: row.id,
      title: row.title,
      price: row.price,
      description: row.description,
      category: row.category,
      subcategory: row.subcategory,
      status: row.status,
      createdAt: row.createdAt,
      images,
      owner: {
        id: row.userId,
        name: row.userName,
        email: row.userEmail,
        profilePic: row.userProfilePic || '/uploads/defaultprofile.webp'
      }
    };

    res.json(listing);
  });
});

app.delete('/api/admin/listings/:id', (req, res) => {
  const listingId = req.params.id;
  const { reason } = req.body;

  if (!reason || reason.trim() === '') {
    return res.status(400).json({ message: 'Ban reason is required.' });
  }

  const sql = `
    UPDATE listings 
    SET status = 'Banned', banReason = ?
    WHERE item_id = ?
  `;

  db.query(sql, [reason, listingId], (err, result) => {
    if (err) {
      console.error('Error banning listing:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Listing not found' });
    }

    res.json({ message: 'Listing has been banned (soft deleted)' });
  });
});

app.post('/api/report-user', (req, res) => {
    const reporterId = req.session.user?.id;
    const { userId: reportedUser, reason } = req.body;

    if (!reporterId || !reportedUser || !reason) {
        return res.status(400).json({ error: 'Missing required data' });
    }

    const reportData = {
        reportedUser,
        reporter: reporterId,
        reason,
        status: 'Pending',
        date: new Date()
    };

    const query = `INSERT INTO reports (reportedUser, reporter, reason, status, date) VALUES (?, ?, ?, ?, ?)`;

    db.query(query, [reportData.reportedUser, reportData.reporter, reportData.reason, reportData.status, reportData.date], (err, results) => {
        if (err) {
            console.error('Error inserting report:', err);
            return res.status(500).json({ error: 'Failed to submit report' });
        }

        res.status(200).json({ message: 'Report submitted successfully' });
    });
});

app.get('/api/admin/reports', (req, res) => {
  const { status, search } = req.query;

  let filters = [];
  let params = [];

  // Case-insensitive status filter
  if (status && status.toLowerCase() !== 'all') {
    filters.push('LOWER(r.status) = ?');
    params.push(status.toLowerCase());
  }

  // Search filter for reporter or reported user names
  if (search) {
    filters.push('(reporter.name LIKE ? OR reported.name LIKE ?)');
    params.push(`%${search}%`, `%${search}%`);
  }

  const whereClause = filters.length ? 'WHERE ' + filters.join(' AND ') : '';

  const sql = `
    SELECT 
      r.id,
      r.reason,
      r.status,
      r.date,
      reporter.id AS reporterId,
      reporter.name AS reporterName,
      reporter.profilepic AS reporterProfilePic,
      reported.id AS reportedId,
      reported.name AS reportedName,
      reported.profilepic AS reportedProfilePic
    FROM reports r
    JOIN users reporter ON r.reporter_id = reporter.id
    JOIN users reported ON r.reported_user_id = reported.id
    ${whereClause}
    ORDER BY r.date DESC
  `;

  db.query(sql, params, (err, results) => {
    if (err) {
      console.error('Error loading reports:', err);
      return res.status(500).json({ message: 'Error loading reports' });
    }

    const reports = results.map(r => ({
      id: r.id,
      reason: r.reason,
      resolved: r.status.toLowerCase() === 'resolved',
      date: r.date,
      reporter: {
        id: r.reporterId,
        name: r.reporterName,
        profilePic: r.reporterProfilePic
      },
      reportedUser: {
        id: r.reportedId,
        name: r.reportedName,
        profilePic: r.reportedProfilePic
      }
    }));

    res.json(reports);
  });
});



// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});