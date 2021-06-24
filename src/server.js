import express from "express";
import cors from "cors";
import pg from "pg";
import joi from "joi";
import { v4 as uuid } from "uuid";
import bcrypt from "bcrypt";

const { Pool } = pg;

const connection = new Pool({
    user: "postgres",
    password: "123456",
    host: "localhost",
    port: 5432,
    database: "mywallet",
});

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
    value: joi.integer().required(),
    description: joi.string().required().max(30),
    type: joi.string().required.valid("entrada", "saída"),
});

const server = express();
server.use(cors());
server.use(express.json());

/* Login Route */
server.post("/mywallet/sign-in", async (req, res) => {
    const validation = loginSchema.validate(req.body);
    if (validation.error) {
        res.sendStatus(400);
        return;
    }
    const { email, password } = req.body;
    try {
        const result = connection.query(
            `SELECT * FROM users 
            WHERE email=$1`,
            [email]
        );
        const user = result.rows[0];
        if (user && bcrypt.compareSync(password, user.password)) {
            const token = uuid.v4();

            await connection.query(
                `INSERT INTO sessions ("userId, token)
                VALUES ($1, $2)`,
                [user.id, token]
            );
            res.status(200).send(token);
        } else {
            res.status(404).send(
                "Usuário não encontrado (email ou senha incorretos)."
            );
        }
    } catch (err) {
        console.log(err);
        res.sendStatus(400);
    }
});

/* Register Route */
server.post("mywallet/sign-up", async (req, res) => {
    const validation = registerSchema.validate(req.body);
    if (validation.error) {
        res.sendStatus(400);
        return;
    }
    const { name, email, password } = req.body;
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

/* New Transaction Route */
server.post("mywallet/new-transaction", async (req, res) => {
    const authorization = req.header("Authorization");
    const token = authorization?.replace("Bearer ", "");

    if (!token) return res.sendStatus(401);

    const result = await connection.query(
        `SELECT * FROM sessions
        WHERE token=$1`,
        [token]
    );

    const userId = result.rows.length ? result.rows[0].id : null;

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

server.listen(4000, () => {
    console.log("Server listening on port 4000.");
});
