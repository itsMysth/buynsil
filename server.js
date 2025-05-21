const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const session = require('express-session');
const app = express();

app.use(express.urlencoded({ extended: true }));
const db = mysql.createConnection({
    host: 'localhost',  // Replace with your host
    user: 'root',       // Replace with your MySQL username
    password: 'allen2004',       // Replace with your MySQL password
    database: 'baynsil'  // Replace with your database name
  });
 
  db.connect((err) => {
    if (err) {
      console.error('Error connecting to the database:', err);
    } else {
      console.log('Connected to MySQL database');
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
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
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

app.get('/api/user/items', (req, res) => {
  const userId = req.query.userId; // Get the user ID from query string

  if (!userId) {
    return res.status(400).json({ error: 'User ID is required' });
  }

  // Query the database for the user's items
  const query = 'SELECT * FROM listings WHERE seller_id = ?'; // Adjust table/column names accordingly
  db.execute(query, [userId], (err, results) => {
    if (err) {
      console.error('Database query error:', err);
      return res.status(500).json({ error: 'Database query failed' });
    }

    // Return the items to the client
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

app.post('/chat/send', async (req, res) => {
  const senderId = req.session.user.id
  const { receiverId, content } = req.body;

  if (!senderId || !receiverId || !content) {
    return res.status(400).json({ error: 'Missing data' });
  }

  // Save to DB
  await db.query(
    'INSERT INTO messages (sender_id, receiver_id, content, timestamp) VALUES (?, ?, ?, NOW())',
    [senderId, receiverId, content]
  );

  res.status(200).json({ success: true });
});

app.get('/chat/messages', async (req, res) => {
  const senderId = req.session.user.id
  const receiverId = req.query.receiverId;


  if (!senderId) return res.status(401).json({ error: 'Unauthorized' });
  if (!receiverId) return res.status(400).json({ error: 'receiverId is required' });

  try {
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
    m.content AS last_message,
    m.timestamp AS last_timestamp,
    m.sender_id,
    m.receiver_id
  FROM messages m
  JOIN users u ON 
    (u.id = IF(m.sender_id = ?, m.receiver_id, m.sender_id))
  WHERE (m.sender_id = ? OR m.receiver_id = ?)
    AND m.timestamp = (
      SELECT MAX(m2.timestamp)
      FROM messages m2
      WHERE (m2.sender_id = m.sender_id AND m2.receiver_id = m.receiver_id)
         OR (m2.sender_id = m.receiver_id AND m2.receiver_id = m.sender_id)
    )
  ORDER BY m.timestamp DESC
`;

db.query(query, [userId, userId, userId], (err, results) => {
  if (err) return res.status(500).json({ error: err.message });
  res.json(results);
});
});

app.get('/api/listings', (req, res) => {
        const query = `
        SELECT 
            listings.item_id,
            listings.item_name,
            listings.category,
            listings.seccategory,
            listings.description,
            listings.price,
            listings.image,
            listings.status,
            listings.dateAdded,
            listings.seller_id,
            users.name AS seller_name
        FROM listings
        JOIN users ON listings.seller_id = users.id
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching listings:', err);
            return res.status(500).json({ error: 'Failed to fetch listings' });
        }
        
        res.json(results); // Send results as JSON
    });
});

app.get('/api/searchlistings', (req, res) => {
    const name = req.query.name || '';
    const sql = `SELECT * FROM listings WHERE LOWER(item_name) LIKE ? AND status != 'Sold'`;
    const wildcard = `%${name.toLowerCase()}%`;

    db.query(sql, [wildcard], (err, results) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: 'Database error' });
        } else {
            res.json(results);
        }
    });
});

app.get('/api/sortlistings', async (req, res) => {
    const sort = req.query.sort || 'newest';
    let orderBy = 'item_id DESC'; // default

    switch (sort) {
        case 'price-low':
            orderBy = 'price ASC';
            break;
        case 'price-high':
            orderBy = 'price DESC';
            break;
        case 'name':
            orderBy = 'name ASC';
            break;
        case 'newest':
        default:
            orderBy = 'item_id DESC';
            break;
    }

    const sql = `SELECT * FROM listings WHERE status != 'Sold' ORDER BY ${orderBy}`;
    
    try {
        const [rows] = await db.promise().query(sql);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
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
    db.query(sql, [email], async(err, results) => {
        if(err){
            console.error(err);
            return res.send('Error while checking credentials');
        }

        if(results.length > 0){
            const user = results[0];
            const passwordMatch = await bcrypt.compare(password, user.password);
            if(passwordMatch){
              req.session.user = {
                id: user.id,
                name: user.name,
                email: user.email
              };
                console.log('Session after login:', req.session.user);
                return res.redirect('/homepage');
            } else {
                return res.redirect('/login?error=true');
            }
        }else {
              return res.redirect('/login?error=true');
        }
    })
})

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    const saltRounds = 10;
  
    // Check if email already exists
    const checkEmailSql = 'SELECT * FROM users WHERE email = ?';
    db.query(checkEmailSql, [email], async (err, results) => {
      if (err) {
        console.error(err);
        return res.send('❌ Error checking email.');
      }
  
      if (results.length > 0) {
        // Email exists, redirect back with query
        return res.redirect(`/login?emailExists=true&name=${encodeURIComponent(name)}&email=${encodeURIComponent(email)}`);
      }
  
      // Email is unique, hash password and insert
      try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const insertSql = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
        db.query(insertSql, [name, email, hashedPassword], (err, result) => {
          if (err) {
            console.error(err);
            return res.send('❌ Failed to register.');
          }
          res.redirect('/success');
        });
      } catch (error) {
        console.error(error);
        res.send('❌ Error hashing password.');
      }
    });
});


// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
