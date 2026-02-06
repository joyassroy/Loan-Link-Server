const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 5013;

// Middleware
app.use(cors({
  origin: ['http://localhost:5173'], // REPLACE WITH YOUR LINKS
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.umszehx.mongodb.net/?appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

// Verify Token Middleware
const verifyToken = (req, res, next) => {
  const token = req.cookies?.token;
  console.log('Token received in backend:', token);
  if (!token) {
    return res.status(401).send({ message: 'unauthorized access' });
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: 'unauthorized access' });
    }
    req.user = decoded;
    next();
  });
};

async function run() {
  try {
    await client.connect();
    // Database Collections
    const db = client.db('LoanLinkDB');
    const usersCollection = db.collection('users');
    const loansCollection = db.collection('loans');
    const applicationsCollection = db.collection('applications');

    // --- AUTHENTICATION & JWT ---
   app.post('/jwt', async (req, res) => {
        const user = req.body;
        const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
        
        res.cookie('token', token, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax', // <--- এখানে 'strict' এর বদলে 'lax' দিয়ে দাও
        }).send({ success: true });
    });

    app.post('/logout', (req, res) => {
      res.clearCookie('token', {
        maxAge: 0,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
      }).send({ success: true });
    });

    // --- MIDDLEWARES FOR ROLES ---
    const verifyAdmin = async (req, res, next) => {
      const email = req.user.email;
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      const isAdmin = user?.role === 'admin';
      if (!isAdmin) {
        return res.status(403).send({ message: 'forbidden access' });
      }
      next();
    };

    const verifyManager = async (req, res, next) => {
      const email = req.user.email;
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      const isManager = user?.role === 'manager'; // Only check manager
      // NOTE: Admins might also need access to manager routes, but per requirements, keep strict.
      if (!isManager && user?.role !== 'admin') { 
        return res.status(403).send({ message: 'forbidden access' });
      }
      next();
    };

    // --- USER RELATED API ---
    app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });

    // Check User Role
    app.get('/users/role/:email', verifyToken, async (req, res) => {
      const email = req.params.email;

      // সিকিউরিটি চেক
      if (email !== req.user.email) {
          return res.status(403).send({ message: 'forbidden access' });
      }

      const query = { email: email };
      const user = await usersCollection.findOne(query);

      // 👇 ফিক্স: যদি ইউজার না থাকে, তবুও একটা রেসপন্স পাঠাও
      if (user) {
          res.send({ role: user.role });
      } else {
          // ইউজার ডাটাবেসে না থাকলেও অ্যাপ যেন ক্র্যাশ না করে
          res.send({ role: 'borrower' }); 
      }
    });

    app.post('/users', async (req, res) => {
      const user = req.body;
      
      // ১. চেক করা ইউজার অলরেডি আছে কিনা
      const query = { email: user.email };
      const existingUser = await usersCollection.findOne(query);
      if (existingUser) {
        return res.send({ message: 'user already exists', insertedId: null });
      }

      // ২. না থাকলে নতুন ইউজার হিসেবে সেভ করা
      const result = await usersCollection.insertOne(user);
      res.send(result);
    });
// Update User Profile (Name & Photo)
    app.patch('/users/update/:email', verifyToken, async (req, res) => {
        const email = req.params.email;
        const user = req.body;
        
        // Security Check
        if (email !== req.user.email) {
            return res.status(403).send({ message: 'forbidden access' });
        }

        const filter = { email: email };
        const updatedDoc = {
            $set: {
                name: user.name,
                // আমরা ডাটাবেসে photoURL নামেই সেভ করি, যদি তোমার স্কিমা ভিন্ন হয় তবে চেক করো
                image: user.photoURL 
            }
        };
        const result = await usersCollection.updateOne(filter, updatedDoc);
        res.send(result);
    });
    // Admin: Update User Role (or Suspend)
    app.patch('/users/admin/:id', verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const { role } = req.body; // role can be 'admin', 'manager', 'borrower'
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: { role: role }
      };
      const result = await usersCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });
    // Manager: Get Pending Applications
    app.get('/applications/pending', verifyToken, verifyManager, async (req, res) => {
      const query = { status: 'pending' };
      const result = await applicationsCollection.find(query).toArray();
      res.send(result);
    });

    // Server: Update Application to Paid
app.patch('/applications/payment/:id', verifyToken, async (req, res) => {
    const id = req.params.id;
    const paymentInfo = req.body;
    const filter = { _id: new ObjectId(id) };
    const updatedDoc = {
        $set: {
            paymentStatus: 'paid',
            transactionId: paymentInfo.transactionId
        }
    };
    const result = await applicationsCollection.updateOne(filter, updatedDoc);
    res.send(result);
});

// Borrower: Get My Applications
// GET: Applications (Admin sees all, User sees theirs)
    app.get('/applications', verifyToken, async (req, res) => {
        try {
            const email = req.query.email; // ইউজার যে ইমেইল দিয়ে খুঁজছে

            let query = {};

            if (email) {
                // টোকেন চেক
                if (req.user.email !== email) {
                    return res.status(403).send({ message: 'forbidden access' });
                }
                
                // 🔥 CHANGE: ডাটাবেসে এখন ফিল্ডের নাম 'email', তাই কুয়েরিও হবে 'email' দিয়ে
                query = { email: email }; 
            }

            const result = await applicationsCollection.find(query).toArray();
            res.send(result);

        } catch (error) {
            console.error("Error fetching applications:", error);
            res.status(500).send({ message: "Internal Server Error" });
        }
    });
    app.get('/applications/my-application', verifyToken, async (req, res) => {
      try {
          const email = req.query.email;
          
          // 1. Debugging: Console log to see if hit
          console.log("Fetching applications for:", email);

          // 2. Security Check
          if (!req.user) {
              return res.status(403).send({ message: 'User not found in token' });
          }
          if (req.user.email !== email) {
              return res.status(403).send({ message: 'forbidden access' });
          }

          const query = { email: email };
          
          // 3. Database Call
          const result = await applicationsCollection.find(query).toArray();
          res.send(result);

      } catch (error) {
          // 4. Print the Real Error in Terminal
          console.error("Error inside /applications/my-application:", error); 
          res.status(500).send({ message: 'Internal Server Error' });
      }
    });
    // Manager: Get Approved Applications Only
    app.get('/applications/approved', verifyToken, verifyManager, async (req, res) => {
      const query = { status: 'approved' };
      const result = await applicationsCollection.find(query).toArray();
      res.send(result);
    });
// Get Single Application by ID (For Payment Page)
    app.get('/applications/:id', verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await applicationsCollection.findOne(query);
      res.send(result);
    });

// Admin: Toggle "Show on Home"
    app.patch('/loans/featured/:id', verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const { showOnHome } = req.body;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: { showOnHome: showOnHome }
      };
      const result = await loansCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });


    // --- LOANS API ---
    
    // Public: Get all loans (for Home & All Loans page)
    app.get('/loans', async (req, res) => {
      const filter = req.query.category ? { category: req.query.category } : {};
      const result = await loansCollection.find(filter).toArray();
      res.send(result);
    });

    // Public: Get Single Loan
    app.get('/loans/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await loansCollection.findOne(query);
      res.send(result);
    });

    // Manager: Add Loan
    app.post('/loans', verifyToken, verifyManager, async (req, res) => {
      const loan = req.body;
      const result = await loansCollection.insertOne(loan);
      res.send(result);
    });

    // Admin/Manager: Delete Loan
    app.delete('/loans/:id', verifyToken, verifyManager, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await loansCollection.deleteOne(query);
      res.send(result);
    });
    // Admin: Get All Applications
    app.get('/applications', verifyToken, verifyAdmin, async (req, res) => {
      const result = await applicationsCollection.find().toArray();
      res.send(result);
    });

    

    // --- APPLICATION API ---

    // Borrower: Apply for loan
    app.post('/applications', verifyToken, async (req, res) => {
      const application = req.body;
      // Add default status
      application.status = 'pending'; 
      application.appliedDate = new Date();
      const result = await applicationsCollection.insertOne(application);
      res.send(result);
    });

    

    

    // Manager: Approve/Reject Application
    app.patch('/applications/status/:id', verifyToken, verifyManager, async (req, res) => {
      const id = req.params.id;
      const { status } = req.body; // 'approved' or 'rejected'
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: { status: status }
      };
      const result = await applicationsCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });

    // --- PAYMENT INTENT (STRIPE) ---
    app.post('/create-payment-intent', verifyToken, async (req, res) => {
      try {
          const { price } = req.body;
          
          // Validation check
          if (!price || typeof price !== 'number') {
              return res.status(400).send({ error: "Invalid price" });
          }

          // Math.round is safer than parseInt for currency (e.g. 10.99)
          const amount = Math.round(price * 100); 

          const paymentIntent = await stripe.paymentIntents.create({
            amount: amount,
            currency: 'usd',
            payment_method_types: ['card']
          });

          res.send({
            clientSecret: paymentIntent.client_secret
          });

      } catch (error) {
          console.log("Stripe Error:", error);
          res.status(500).send({ error: error.message });
      }
    });

    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('LoanLink Server is running');
});

app.listen(port, () => {
  console.log(`LoanLink is sitting on port ${port}`);
});