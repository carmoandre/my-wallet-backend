import supertest from "supertest";
import app from "../src/app.js";
import connection from "../src/database.js";

let data = [];
const dataSessions = [];

beforeAll(async () => {
    data = await connection.query("SELECT * FROM sessions");
    dataSessions.push(data.rows[0]);
});

beforeEach(async () => {
    await connection.query("DELETE FROM sessions");
});

afterAll(async () => {
    await connection.query("DELETE FROM sessions");

    for (let i = 0; i < dataSessions.length; i++) {
        const userId = dataSessions[i].userId;
        const token = dataSessions[i].token;
        await connection.query(
            `
            INSERT INTO sessions ("userId", token) VALUES ($1, $2)
        `,
            [userId, token]
        );
    }

    connection.end();
});

describe("POST /mywallet/sign-in", () => {
    it("returns status 200 for valid params", async () => {
        const body = {
            name: "Fulano",
            email: "fulano@email.com",
            password: "123456",
        };

        await supertest(app).post("/mywallet/sign-up").send(body);

        const response = await supertest(app).post("/mywallet/sign-in").send({
            email: "fulano@email.com",
            password: "123456",
        });
        expect(response.status).toEqual(200);
        expect(response.body).toEqual(
            expect.objectContaining({
                name: expect.any(String),
                token: expect.any(String),
            })
        );
    });

    it("returns status 404 for invalid params", async () => {
        const body = {
            name: "Fulano",
            email: "fulano@email.com",
            password: "123456",
        };

        await supertest(app).post("/mywallet/sign-up").send(body);

        const response = await supertest(app).post("/mywallet/sign-in").send({
            email: "fulano@email.com",
            password: "senha_incorreta",
        });

        expect(response.status).toEqual(404);
    });
});
