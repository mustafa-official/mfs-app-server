const express = require('express');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
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
        const transactionCollection = client.db("mfsAppDB").collection('transaction');

        // JWT token generation middleware
        const generateAccessToken = (id, role) => {
            return jwt.sign({ id, role }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
        };

        const verifyToken = (req, res, next) => {
            if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
                return res.status(401).json({ message: 'Unauthorized' });
            }
            const token = req.headers.authorization.split(' ')[1];
            jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
                if (err) {
                    return res.status(401).json({ message: 'Unauthorized' });
                }
                req.user = decoded;
                next();
            });
        };

        // Register endpoint
        app.post('/register', async (req, res) => {
            const { name, email, mobile, role, pin, balance, status } = req.body;
            const saltRound = 10;
            const hash_pin = await bcrypt.hash(pin, saltRound);
            const user = { name, email, mobile, role, pin: hash_pin, balance, status };
            const result = await userCollection.insertOne(user);

            if (result.insertedId) {
                const token = generateAccessToken(result.insertedId, user.role);
                res.send({ data: "register successful", token });
            } else {
                res.send({ data: "registration failed" });
            }
        });

        // Login
        app.post('/login', async (req, res) => {
            const { identifier, pin } = req.body;
            const user = await userCollection.findOne({
                $or: [{ email: identifier }, { mobile: identifier }],
            });

            if (user) {
                const isMatch = await bcrypt.compare(pin, user.pin);
                if (isMatch) {
                    const token = generateAccessToken(user._id, user.role);
                    res.send({ data: "match", token });
                } else {
                    res.send({ data: "Invalid Pin" });
                }
            } else {
                res.send({ data: "User Not Found" });
            }
        });


        app.get('/user/:identifier', verifyToken, async (req, res) => {
            const identifier = req.params.identifier;
            const user = await userCollection.findOne({
                $or: [{ email: identifier }, { mobile: identifier }],
            });

            if (user) {
                res.send(user);
            } else {
                res.status(404).send({ message: "User Not Found" });
            }
        });

        //all user and agent (Admin) -------
        app.get('/users', async (req, res) => {
            const searchValue = req.query.name?.toLowerCase() || "";
            const result = await userCollection.find({ name: { $regex: new RegExp(searchValue, 'i') }, role: { $in: ['user', 'agent'] } }).toArray();
            res.send(result);
        })

        //activate user (Admin) -------
        app.patch('/user/:id', async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const update = {
                $inc: { balance: 40 },
                $set: { status: 'activate' }
            }
            const result = await userCollection.updateOne(filter, update);
            res.send(result)
        })

        //block user (Admin) -------
        app.patch('/block-user/:id', async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const update = {
                $set: { status: 'block' }
            }
            const result = await userCollection.updateOne(filter, update);
            res.send(result)
        })

        //send money -------
        app.patch('/send-money', async (req, res) => {
            const { mobile, amount, pin, userEmail } = req.body;

            // Find logged-in user by their mobile number
            const loggedInUser = await userCollection.findOne({ email: userEmail });

            if (!loggedInUser) {
                return res.send({ data: "User not found" });
            }

            // Compare the provided pin with the hashed pin in the database
            const isMatch = await bcrypt.compare(pin, loggedInUser.pin);

            if (!isMatch) {
                return res.send({ data: "Invalid Pin" });
            }

            // Find the target user by their mobile number
            const targetUser = await userCollection.findOne({ mobile, role: 'user' });

            if (!targetUser) {
                return res.send({ data: "Invalid account" });
            }

            // Calculate the final amount, including the fee if applicable
            let finalAmount = parseInt(amount, 10);
            const fee = finalAmount > 100 ? 5 : 0;
            finalAmount = finalAmount - fee;

            // Update the target users balance
            const filter = { _id: new ObjectId(targetUser._id) };
            const update = {
                $inc: { balance: finalAmount }
            };
            const senderPhone = await userCollection.findOne({ email: userEmail })
            // console.log("sender phoooooooone", senderPhone.mobile);
            const result = await userCollection.updateOne(filter, update);
            const transactionHistory = await transactionCollection.insertOne({ userMobile: senderPhone.mobile, receiverMobile: mobile, amount, type: 'Send Money', date: new Date().toLocaleString() })
            res.send(result)

        });

        //cash out -------
        app.patch('/cash-out', async (req, res) => {
            const { mobile, amount, pin, userEmail } = req.body;
            console.log(mobile, amount, pin, userEmail);
            // Find logged in user by email -------
            const loggedInUser = await userCollection.findOne({ email: userEmail });

            if (!loggedInUser) {
                return res.send({ data: "User not found" });
            }

            // Compare the provided pin with the hashed pin in the database -------
            const isMatch = await bcrypt.compare(pin, loggedInUser.pin);

            if (!isMatch) {
                return res.send({ data: "Invalid Pin" });
            }

            // Find the agent by mobile number -------
            const agent = await userCollection.findOne({ mobile, role: 'agent' });

            if (!agent) {
                return res.send({ data: "Invalid agent account" });
            }

            // Calculate the cash-out amount and fee -------
            const fee = amount * 0.015;
            const totalDeduct = amount + fee;

            if (loggedInUser.balance < totalDeduct) {
                return res.send({ data: "Insufficient balance" });
            }

            // Update balances: deduct from user and add to agent-------
            const userUpdate = {
                $inc: { balance: -totalDeduct }
            };
            const agentUpdate = {
                $inc: { balance: amount + fee }
            };

            const userResult = await userCollection.updateOne({ _id: new ObjectId(loggedInUser._id) }, userUpdate);
            const agentResult = await userCollection.updateOne({ _id: new ObjectId(agent._id) }, agentUpdate);
            const transactionHistory = await transactionCollection.insertOne({ userMobile: loggedInUser.mobile, receiverMobile: mobile, amount, type: 'Cash Out', date: new Date().toLocaleString() })
            res.send({
                userResult,
                agentResult,
                data: "Cash out successful"
            });



        });

        //cashin request to  agent
        app.post('/cashin-request', async (req, res) => {
            const { mobile, amount, userMobile } = req.body;
            const agent = await userCollection.findOne({ mobile, role: 'agent' });
            if (!agent) {
                return res.send({ data: 'Invalid Agent' });
            }

            const cashInRequest = {
                userMobile,
                receiverMobile: mobile,
                receiverEmail: agent.email,
                amount,
                status: 'pending',
                type: 'Cash In',
                date: new Date().toLocaleString(),
            };
            const result = await transactionCollection.insertOne(cashInRequest);
            res.send(result);

        })

        //get all transaction request in agent role
        app.get('/transaction-request/:email', async (req, res) => {
            const email = req.params.email;
            const query = { receiverEmail: email, status: { $in: ['pending', 'success'] } }
            const result = await transactionCollection.find(query).toArray();
            res.send(result);
        })

        // cashin-approve in agent role
        app.patch('/cashin-approve/:id', async (req, res) => {
            const id = req.params.id;
            const { userMobile, receiverMobile, amount, } = req.body;


            const userUpdate = { $inc: { balance: amount } };
            const userResult = await userCollection.updateOne({ mobile: userMobile }, userUpdate);

            const agentUpdate = { $inc: { balance: -amount } };
            const agentResult = await userCollection.updateOne({ mobile: receiverMobile }, agentUpdate);

            const transactionResult = await transactionCollection.updateOne({ _id: new ObjectId(id) }, { $set: { status: 'success' } });
            res.send({ userResult, agentResult, transactionResult })

        })

        //transaction history
        app.get('/transaction-history/:mobile', async (req, res) => {
            const mobile = req.params.mobile;
            const query = { userMobile: mobile };
            const result = await transactionCollection.find(query).sort({ date: -1 }).limit(10).toArray();
            res.send(result);

        })
        
        //transaction history for agent
        app.get('/trans-history-agent', async (req, res) => {
            const mobile = req.query.mobile;
            const query = { receiverMobile: mobile };
            const result = await transactionCollection.find(query).sort({ date: -1 }).limit(20).toArray();
            res.send(result);

        })

        //get all transaction in admin
        app.get('/transactions', async (req, res) => {
            const result = await transactionCollection.find().toArray();
            res.send(result);
        })


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