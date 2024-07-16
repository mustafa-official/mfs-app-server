const express = require('express');
const { MongoClient, ServerApiVersion } = require('mongodb');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();
const port = process.env.PORT || 5000;

//middleware
app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.elzgrcu.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();
        const userCollection = client.db("mfsAppDB").collection('users');

        // jwt 
        // app.post('/jwt', async (req, res) => {
        //     const user = req.body;
        //     const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        //         expiresIn: '1h'
        //     })
        //     res.send({ token })
        // })

        //middleware verify
        const verifyToken = (req, res, next) => {
            // console.log('inside verify token', req.headers);
            if (!req.headers.authorization) {
                return res.status(401).send({ message: 'unauthorize access' })
            }
            const token = req.headers.authorization.split(' ')[1]
            jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
                if (err) {
                    return res.status(401).send({ message: 'unauthorize access' })
                }
                req.decoded = decoded;
                next();
            })

        }

        //register
        // app.post('/register', async (req, res) => {
        //     const { name, email, mobile, role, pin } = req.body;
        //     //hash pin
        //     const saltRound = 10;
        //     const hash_pin = await bcrypt.hash(pin, saltRound);
        //     const user = { name, email, mobile, role, pin: hash_pin }
        //     const result = await userCollection.insertOne(user);
        //     res.send(result)
        // })

        // Login
        // app.post('/login', async (req, res) => {
        //     const { identifier, pin } = req.body;
        //     const user = await userCollection.findOne({
        //         $or: [{ email: identifier }, { mobile: identifier }],
        //     });

        //     if (user) {
        //         const isMatch = await bcrypt.compare(pin, user.pin);
        //         if (isMatch) {
        //             res.send({ data: "match" });
        //         } else {
        //             res.send({ data: "Invalid Pin" });
        //         }
        //     } else {
        //         res.send({ data: "User Not Found" });
        //     }
        // });

        app.post('/register', async (req, res) => {
            const { name, email, mobile, role, pin } = req.body;
            const saltRound = 10;
            const hash_pin = await bcrypt.hash(pin, saltRound);
            const user = { name, email, mobile, role, pin: hash_pin };
            const result = await userCollection.insertOne(user);

            if (result.insertedId) {
                const token = jwt.sign({ id: result.insertedId, role: user.role }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
                res.send({ data: "register successful", token });
            } else {
                res.send({ data: "registration failed" });
            }
        });

        app.post('/login', async (req, res) => {
            const { identifier, pin } = req.body;
            const user = await userCollection.findOne({
                $or: [{ email: identifier }, { mobile: identifier }],
            });

            if (user) {
                const isMatch = await bcrypt.compare(pin, user.pin);
                if (isMatch) {
                    const token = jwt.sign({ id: user._id, role: user.role }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
                    res.send({ data: "match", token });
                } else {
                    res.send({ data: "Invalid Pin" });
                }
            } else {
                res.send({ data: "User Not Found" });
            }
        });








        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);



app.get('/', (req, res) => {
    res.send('mfs app is running')
})

app.listen(port, () => {
    console.log(`mfs app running port is ${port}`);
})