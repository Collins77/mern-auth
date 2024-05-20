require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const userRoute = require("./routes/userRoutes");
const errorHandler = require("./middleware/errorMiddleware");

const app = express()

// Middlewares
app.use(express.json())
app.use(express.urlencoded({extended: false}))
app.use(cookieParser())
app.use(bodyParser.json())
app.use(
    cors({
        origin: [
            "http://localhost:3000",
            "https://kaboii.com"
        ],
        credentials: true
    })
)

// Routes
app.use("/api/users", userRoute)

app.get("/", (req, res) => {
    res.send("Home Page")
})

// ErrorHandler
app.use(errorHandler);

const PORT = process.env.PORT || 3500
mongoose.connect(process.env.MONGO_URI).then(() => {
    app.listen(PORT, () => {
        console.log(`server is running on port ${PORT}`)
    })
}).catch((err) => console.log(err))