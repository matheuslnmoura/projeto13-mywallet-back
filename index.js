/* eslint-disable no-console */
import express, { json } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { MongoClient, ObjectId } from 'mongodb';
import chalk from 'chalk';
import joi from 'joi';
import bcrypt from 'bcrypt';
import { v4 as uuid } from 'uuid';

const app = express();
app.use(json());
app.use(cors());
dotenv.config();

// Data Base Connection
// eslint-disable-next-line no-unused-vars
let dataBase = null;

const mongoClient = new MongoClient(process.env.MONGO_URL);
const dbConnection = mongoClient.connect();

dbConnection.then(() => {
    dataBase = mongoClient.db(process.env.DATA_BASE);
    console.log(chalk.green.bold('Successful connection with MongoDB'));
});

dbConnection.catch(() => {
    console.log(chalk.red.bold('Connection with MongoDB failed'));
});

// SignUp

app.post('/signUp', async (req, res) => {
    const user = req.body;
    const { email } = user;
    const passwordHash = bcrypt.hashSync(user.password, 10);
    const userSchema = joi.object({
        name: joi.string().required(),
        email: joi.string().email().required(),
        password: joi.string().min(8).required(),
    });
    const { error } = userSchema.validate(user, { abortEarly: false });
    if (error) {
        console.log(chalk.red.bold('Fill all informations correctly'));
        return res.status(422).send(error.details);
    }

    const dataBaseUser = await dataBase.collection('users').findOne({ email });

    if (dataBaseUser) {
        console.log(chalk.red.bold('This email has already been registered'));
        return res.status(403).send('Existing Email');
    }

    try {
        const registredUser = { name: user.name, email: user.email };
        await dataBase.collection('users').insertOne({ ...user, password: passwordHash });
        console.log(chalk.green.bold('User Registred on data base'));
        return res.status(201).send(registredUser);
    } catch (e) {
        console.log(e);
        return res.status(500).send('Erro ao registrar o usuário!', e);
    }
});

// Login
// eslint-disable-next-line consistent-return
app.post('/login', async (req, res) => {
    const user = req.body;
    const { email, password } = user;
    const userSchema = joi.object({
        email: joi.string().email().required(),
        password: joi.string().min(8).required(),
    });
    const { error } = userSchema.validate(user, { abortEarly: false });
    if (error) {
        console.log(chalk.red.bold('Fill all the login informations correctly'));
        return res.status(422).send(error.details);
    }

    try {
        const dataBaseUser = await dataBase.collection('users').findOne({ email });
        if (dataBaseUser && bcrypt.compareSync(password, dataBaseUser.password)) {
            const token = uuid();
            const loginResponse = { name: dataBaseUser.name, email: dataBaseUser.email, token };
            await dataBase.collection('sessions').insertOne({
                ...loginResponse,
                // eslint-disable-next-line no-underscore-dangle
                userId: dataBaseUser._id,
            });
            console.log(chalk.green.bold('User found on data base and password secured'));
            return res.status(201).send(loginResponse);
        }
        if (dataBaseUser === null) {
            console.log(chalk.red.bold('User not found on data base'));
            return res.status(404).send('User not found');
        }
        if (!bcrypt.compareSync(password, dataBaseUser.password)) {
            console.log(chalk.red.bold('Incorrect Password'));
            return res.status(422).send('Incorrect Password');
        }
    } catch (e) {
        console.log(e);
        return res.status(500).send('Erro ao registrar o usuário!', e);
    }
});

// Get Finances Log

app.get('/finances', async (req, res) => {
    const { authorization } = req.headers;
    const token = authorization?.replace('Bearer ', '');

    if (!token) return res.status(401).send('Invalid Token. Please Login Again');

    try {
        const sessionUser = await dataBase.collection('sessions').findOne({ token });
        const { userId } = sessionUser;
        const entries = await dataBase.collection('entries').find({ userId }).toArray();

        return res.status(200).send(entries);
    } catch (e) {
        console.log(e);
        return res.status(500).send('Could not get your entries. Try again later', e);
    }
});

// Register Entry

app.post('/finances', async (req, res) => {
    const { authorization } = req.headers;
    const token = authorization?.replace('Bearer ', '');

    if (!token) return res.status(401).send('Invalid Token. Please Login Again');

    const sessionUser = await dataBase.collection('sessions').findOne({ token });

    const newLog = req.body;
    const newLogSchema = joi.object({
        date: joi.string().required(),
        description: joi.string().min(3).required(),
        type: joi.string().required(),
        value: joi.number().required(),
    });
    const { error } = newLogSchema.validate(newLog, { abortEarly: false });
    if (error) {
        console.log(chalk.red.bold('Fill all the entry informations correctly'));
        return res.status(422).send(error.details);
    }

    try {
        const dataBaseEntry = await dataBase.collection('entries').insertOne({
            ...newLog,
            userId: sessionUser.userId,
        });

        const { insertedId } = dataBaseEntry;
        const entry = await dataBase.collection('entries').findOne({ _id: insertedId });

        return res.status(201).send(entry);
    } catch (e) {
        console.log(e);
        return res.status(500).send('Could not register your entries. Try again later', e);
    }
});

// Delete Document

app.delete('/finances/:entryId', async (req, res) => {
    const { entryId } = req.params;
    const { authorization } = req.headers;
    const token = authorization?.replace('Bearer ', '');

    try {
        const sessionUser = await dataBase.collection('sessions').findOne({ token });

        if (!token || !sessionUser) return res.status(401).send('Invalid Token. Please Login Again');

        const entry = await dataBase.collection('entries').deleteOne({ _id: new ObjectId(entryId) });

        return res.status(200).send(entry);
    } catch (e) {
        console.log(e);
        return res.status(500).send('Could not delete your entry. Try again later', e);
    }
});

// Modificate Document

app.put('/finances/:entryId', async (req, res) => {
    const { entryId } = req.params;
    const { authorization } = req.headers;
    const updatedInfo = req.body;
    const token = authorization?.replace('Bearer ', '');

    try {
        const sessionUser = await dataBase.collection('sessions').findOne({ token });

        if (!token || !sessionUser) return res.status(401).send('Invalid Token. Please Login Again');

        const document = await dataBase.collection('entries').findOne({ _id: new ObjectId(entryId) });

        if (!document) return res.status(404).send('Not able to find this entry. Try again later');

        const updatedDocument = await dataBase.collection('entries').updateOne({
            _id: new ObjectId(entryId),
        }, { $set: updatedInfo });

        return res.status(200).send(updatedDocument);
    } catch (e) {
        console.log(e);
        return res.status(500).send('Could not update your entry. Try again later', e);
    }
});

app.listen(process.env.PORT, () => {
    console.log(chalk.blue.bold('Server online on port', process.env.PORT));
});
