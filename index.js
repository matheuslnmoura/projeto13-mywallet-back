import express, { json } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { MongoClient } from 'mongodb';
import chalk from 'chalk';
import joi from 'joi';
import bcrypt from 'bcrypt';

const app = express();
app.use(json());
app.use(cors());
dotenv.config();

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
        console.log(registredUser);
        return res.status(201).send(registredUser);
    } catch (e) {
        console.log(e);
        return res.status(500).send('Erro ao registrar o usuário!', e);
    }
});

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
            console.log(chalk.green.bold('User found on data base and password secured'));
            return res.status(201).send(dataBaseUser);
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

app.listen(process.env.PORT, () => {
    console.log(chalk.blue.bold('Server online on port', process.env.PORT));
});
