const express = require("express");
const mysql = require('mysql2/promise');
const fs = require('fs');
const bcrypt = require("bcrypt");

const app = express();

const pool = mysql.createPool({
  host: process.env.DB_host,
  port: process.env.DB_port,
  user: "avnadmin",
  password: process.env.DB_password,
  database: "defaultdb",
  ssl: {ca: fs.readFileSync(__dirname + process.env.DB_ssl)} 
});

app.post("/signup", async (appReq, appRes) => 
{
  try {
    const userExistsQuery = "SELECT user_id FROM user_pass WHERE username = ?";
    const [userID, fields] = await pool.execute(userExistsQuery, [appReq.query.username]);

    console.log(userID);
    console.log(fields);

    if (userID.length != 0)
    {
      appRes.status(409);
      appRes.send("This usermane is already taken");
    }
    else
    {
      const createUserQuery = "INSERT INTO user_pass (username, pass_hash) VALUES (?, ?);"

      const hashedPassword = bcrypt.hashSync(appReq.query.password, 10);

      await pool.execute(createUserQuery, [appReq.query.username, hashedPassword]);

      appRes.status(200);
      appRes.send("Signup successful!");

    }

  }
  catch (e)
  {
    console.log(e);
    appRes.sendStatus(500);
  }
});

app.post("/login", async (appReq, appRes) =>
{  try
  {
    const GetPasswordQuery = "select pass_hash from user_pass where username = ?";
    const [hashedPassword, fields] = await pool.execute(GetPasswordQuery, [appReq.query.username]);

    if (hashedPassword.length == 0)
    {
      appRes.status(401);
      appRes.send("Wrong username");
    }
    else
    {
      const rightPass = bcrypt.compareSync(appReq.query.password, hashedPassword[0].pass_hash);
      if (rightPass)
      {
        appRes.status(200);
        appRes.send("Login successful")
      } else {
        appRes.status(401);
        appRes.send("Wrong password");
      }
    }

  }
  catch (e)
  {
    console.log(e);
    appRes.sendStatus(500);
  }
});

app.listen(8080);