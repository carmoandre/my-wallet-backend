import express from "express";
import cors from "cors";
import joi from "joi";
import { v4 as uuid } from "uuid";
import bcrypt from "bcrypt";
import dayjs from "dayjs";
import connection from "./database.js";

const loginSchema = joi.object({
    email: joi
        .string()
        .required()
        .email({ minDomainSegments: 2, tlds: { allow: false } }),
    password: joi.string().required(),
});

const registerSchema = joi.object({
    name: joi.string().required(),
    email: joi
        .string()
        .required()
        .email({ minDomainSegments: 2, tlds: { allow: false } }),
    password: joi.string().required(),
});

const transactionSchema = joi.object({
    value: joi.number().required(),
    description: joi.string().required().max(20),
    type: joi.string().required().valid("entrada", "saída"),
});

const app = express();
app.use(cors());
app.use(express.json());

/* Register Route */
app.post("/mywallet/sign-up", async (req, res) => {
    const validation = registerSchema.validate(req.body);
    const { name, email, password } = req.body;

    if (validation.error) {
        res.sendStatus(400);
        return;
    }

    const result = await connection.query(
        `SELECT * FROM users 
        WHERE email=$1`,
        [email]
    );

    if (result.rows.length) {
        res.sendStatus(409);
        return;
    }

    const hash = bcrypt.hashSync(password, 12);
    try {
        await connection.query(
            `INSERT INTO users (name, email, password)
            VALUES ($1, $2, $3)`,
            [name, email, hash]
        );
        res.sendStatus(201);
    } catch (err) {
        console.log(err);
        res.sendStatus(400);
    }
});

/* Login Route */
app.post("/mywallet/sign-in", async (req, res) => {
    const validation = loginSchema.validate(req.body);
    if (validation.error) {
        res.sendStatus(400);
        return;
    }
    const { email, password } = req.body;
    try {
        const result = await connection.query(
            `SELECT * FROM users 
            WHERE email=$1`,
            [email]
        );
        const user = result.rows[0];
        if (user && bcrypt.compareSync(password, user.password)) {
            const token = uuid();

            await connection.query(
                `INSERT INTO sessions ("userId", token)
                VALUES ($1, $2)`,
                [user.id, token]
            );
            res.status(200).send({ name: user.name, token });
        } else {
            res.status(404).send(
                "Usuário não encontrado (email ou senha incorretos)."
            );
        }
    } catch (err) {
        console.log(err);
        res.sendStatus(500);
    }
});

/* Show Transactions Route */
app.get("/mywallet/show-transactions", async (req, res) => {
    const authorization = req.header("Authorization");
    const token = authorization?.replace("Bearer ", "");

    if (!token) return res.sendStatus(401);

    const result = await connection.query(
        `SELECT * FROM sessions
        WHERE token=$1`,
        [token]
    );

    const userId = result.rows.length ? result.rows[0].userId : null;
    if (!userId) return res.status(404).send("Usuário não encontrado");

    try {
        const transactions = await connection.query(
            `SELECT * FROM transactions WHERE "userId"=$1 ORDER BY date`,
            [userId]
        );
        res.status(200).send(
            transactions.rows.length
                ? transactions.rows.map((transaction) => {
                      return {
                          ...transaction,
                          date: dayjs(transaction.date).format("DD/MM"),
                      };
                  })
                : null
        );
    } catch (err) {
        console.log(err);
        res.sendStatus(400);
    }
});

/* New Transaction Route */
app.post("/mywallet/new-transaction", async (req, res) => {
    const authorization = req.header("Authorization");
    const token = authorization?.replace("Bearer ", "");

    if (!token) return res.sendStatus(401);

    const result = await connection.query(
        `SELECT * FROM sessions
        WHERE token=$1`,
        [token]
    );

    const userId = result.rows.length ? result.rows[0].userId : null;

    if (!userId) return res.status(404).send("Usuário não encontrado");

    const validation = transactionSchema.validate(req.body);
    if (validation.error) {
        res.sendStatus(400);
        return;
    }
    const { value, description, type } = req.body;
    try {
        connection.query(
            `INSERT INTO transactions ("userId", date, value, description, type)
            VALUES ($1, NOW(), $2, $3, $4)`,
            [userId, value, description, type]
        );
        res.sendStatus(201);
    } catch (err) {
        console.log(err);
        res.sendStatus(400);
    }
});

/* Logout Route */
app.delete("/mywallet/end-sessions", async (req, res) => {
    const authorization = req.header("Authorization");
    const token = authorization?.replace("Bearer ", "");

    if (!token) return res.sendStatus(401);

    const result = await connection.query(
        `SELECT * FROM sessions
        WHERE token=$1`,
        [token]
    );

    const userId = result.rows.length ? result.rows[0].userId : null;

    if (!userId) return res.status(404).send("Usuário não encontrado");

    try {
        await connection.query(
            `DELETE FROM sessions 
            WHERE "userId"=$1`,
            [userId]
        );
        res.sendStatus(204);
    } catch (err) {
        console.log(err);
        res.sendStatus(500);
    }
});

export default app;
