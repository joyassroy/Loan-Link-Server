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
  origin: [
    'http://localhost:5173', 
    'https://assignment-11-468e1.web.app'
     // তোমার Vercel Frontend Link (যদি থাকে)
    // ভবিষ্যতে তোমার ফ্রন্টএন্ড যেখানে ডিপ্লয় করবে, সেই লিংক এখানে দিবে
  ],
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
  // console.log('Token received in backend:', token);
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
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect(); // Vercel এ কানেকশন বারবার ওপেন না করাই ভালো, তাই এটা কমেন্ট রাখতে পারো বা রাখতেও পারো।

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
            secure: true, // লাইভ সার্ভারে true হবে
            sameSite: 'none',
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
      const isManager = user?.role === 'manager'; 
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

    app.get('/users/role/:email', verifyToken, async (req, res) => {
      const email = req.params.email;
      if (email !== req.user.email) {
          return res.status(403).send({ message: 'forbidden access' });
      }
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      if (user) {
          res.send({ role: user.role });
      } else {
          res.send({ role: 'borrower' }); 
      }
    });

    app.post('/users', async (req, res) => {
      const user = req.body;
      const query = { email: user.email };
      const existingUser = await usersCollection.findOne(query);
      if (existingUser) {
        return res.send({ message: 'user already exists', insertedId: null });
      }
      const result = await usersCollection.insertOne(user);
      res.send(result);
    });

    app.patch('/users/update/:email', verifyToken, async (req, res) => {
        const email = req.params.email;
        const user = req.body;
        if (email !== req.user.email) {
            return res.status(403).send({ message: 'forbidden access' });
        }
        const filter = { email: email };
        const updatedDoc = {
            $set: {
                name: user.name,
                image: user.photoURL 
            }
        };
        const result = await usersCollection.updateOne(filter, updatedDoc);
        res.send(result);
    });

    app.patch('/users/admin/:id', verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const { role } = req.body;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: { role: role }
      };
      const result = await usersCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });

    app.get('/applications/pending', verifyToken, verifyManager, async (req, res) => {
      const query = { status: 'pending' };
      const result = await applicationsCollection.find(query).toArray();
      res.send(result);
    });

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

    app.get('/applications', verifyToken, async (req, res) => {
        try {
            const email = req.query.email; 
            let query = {};
            if (email) {
                if (req.user.email !== email) {
                    return res.status(403).send({ message: 'forbidden access' });
                }
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
          if (!req.user) {
              return res.status(403).send({ message: 'User not found in token' });
          }
          if (req.user.email !== email) {
              return res.status(403).send({ message: 'forbidden access' });
          }
          const query = { email: email };
          const result = await applicationsCollection.find(query).toArray();
          res.send(result);
      } catch (error) {
          console.error("Error inside /applications/my-application:", error); 
          res.status(500).send({ message: 'Internal Server Error' });
      }
    });

    app.get('/applications/approved', verifyToken, verifyManager, async (req, res) => {
      const query = { status: 'approved' };
      const result = await applicationsCollection.find(query).toArray();
      res.send(result);
    });

    app.get('/applications/:id', verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await applicationsCollection.findOne(query);
      res.send(result);
    });

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
    app.get('/loans', async (req, res) => {
      const filter = req.query.category ? { category: req.query.category } : {};
      const result = await loansCollection.find(filter).toArray();
      res.send(result);
    });

    app.get('/loans/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await loansCollection.findOne(query);
      res.send(result);
    });

    app.post('/loans', verifyToken, verifyManager, async (req, res) => {
      const loan = req.body;
      const result = await loansCollection.insertOne(loan);
      res.send(result);
    });

    app.delete('/applications/:id', verifyToken, verifyAdmin, async (req, res) => {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await applicationsCollection.deleteOne(query);
        res.send(result);
    });

    app.delete('/loans/:id', verifyToken, verifyManager, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await loansCollection.deleteOne(query);
      res.send(result);
    });

    // --- APPLICATION API ---
    app.post('/applications', verifyToken, async (req, res) => {
      const application = req.body;
      application.status = 'pending'; 
      application.appliedDate = new Date();
      const result = await applicationsCollection.insertOne(application);
      res.send(result);
    });

    app.patch('/applications/status/:id', verifyToken, verifyManager, async (req, res) => {
      const id = req.params.id;
      const { status } = req.body; 
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
          if (!price || typeof price !== 'number') {
              return res.status(400).send({ error: "Invalid price" });
          }
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

// ✅ Vercel এর জন্য এটা জরুরি
module.exports = app;