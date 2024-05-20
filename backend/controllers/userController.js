const asyncHandler = require("express-async-handler")
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const { generateToken, hashToken } = require("../utils");
const parser = require("ua-parser-js");
const jwt = require("jsonwebtoken");
const sendEmail = require("../utils/sendEmail");
const Token = require("../models/Token");
const crypto = require("crypto");
const Cryptr = require("cryptr");
const { response } = require("express");

const cryptr = new Cryptr(process.env.CRYPTR_KEY);

const registerUser = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        res.status(400)
        throw new Error("Please fill in all the required fields.")
    }

    if (password.length < 6) {
        res.status(400)
        throw new Error("Password must be at least 6 characters")
    }

    // Check if user exists
    const userExists = await User.findOne({ email })

    if (userExists) {
        res.status(400)
        throw new Error("Email already in use.")
    }

    // get User Agent
    const ua = parser(req.headers['user-agent']);
    const userAgent = [ua.ua]

    // Create New User
    const user = await User.create({
        name,
        email,
        password,
        userAgent
    })

    // Generate Token
    const token = generateToken(user._id)
    res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // id
        sameSite: "none",
        secure: true,
    })

    if (user) {
        const { _id, name, email, phone, bio, photo, role, isVerified } = user

        res.status(200).json({
            _id, name, email, phone, bio, photo, role, isVerified, userAgent, token
        })

    } else {
        res.status(400)
        throw new Error("Invalid User Data")
    }

})

// send verification email
const sendVerificationEmail = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id)

    if (!user) {
        res.status(404);
        throw new Error("User not found")
    }

    if (user.isVerified) {
        res.status(400);
        throw new Error("User already verified")
    }

    // Delete Token if it exists in DB

    let token = await Token.findOne({ userId: user._id })
    if (token) {
        await token.deleteOne()
    }

    // Create Verfication Token and Save
    const verificationToken = crypto.randomBytes(32).toString("hex") + user._id;
    console.log(verificationToken)

    // Hash the token and save
    const hashedToken = hashToken(verificationToken)
    await new Token({
        userId: user._id,
        vToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60 * 1000), // 60 minutes
    }).save()

    // construct verification url
    const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`

    // send verification email
    const subject = "Verify Your Account - Cotek"
    const send_to = user.email
    const send_from = process.env.SMTP_MAIL
    const reply_to = "noreply@cotek.com"
    const template = "verifyEmail"
    const name = user.name
    const link = verificationUrl

    try {
        await sendEmail(subject, send_to, send_from, reply_to, template, name, link)
        res.status(200).json({ message: "Verification Email sent successfully" })
    } catch (error) {
        console.error(error)
        res.status(500)
        throw new Error("Email not sent, please try again")
    }

})

// verify User
const verifyUser = asyncHandler(async (req, res) => {
    const { verificationToken } = req.params;
    const hashedToken = hashToken(verificationToken)

    const userToken = await Token.findOne({
        vToken: hashedToken,
        expiresAt: { $gt: Date.now() }
    })

    if (!userToken) {
        res.status(404);
        throw new Error("Invalid or Expired Token");
    }

    // Find User
    const user = await User.findOne({ _id: userToken.userId })

    if (user.isVerified) {
        res.status(404);
        throw new Error("User already verified");
    }

    // verify the user
    user.isVerified = true;
    await user.save();

    res.status(200).json({ message: "Account verification successful" });

})

const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // validation
    if (!email || !password) {
        res.status(400)
        throw new Error("Please enter all credentials")
    }
    const user = await User.findOne({ email })

    if (!user) {
        res.status(404)
        throw new Error("User not found, please sign up.")
    }

    const passwordIsCorrect = await bcrypt.compare(
        password, user.password
    )
    if (!passwordIsCorrect) {
        res.status(400)
        throw new Error("Invalid email or password");
    }

    // Trigger 2FA for unknown UserAgent
    const ua = parser(req.headers["user-agent"]);
    const thisUserAgent = ua.ua;

    console.log(thisUserAgent);
    const allowedAgent = user.userAgent.includes(thisUserAgent)

    if (!allowedAgent) {
        // Generate 6 digit code
        const loginCode = Math.floor(100000 + Math.random() * 900000)

        // Encrypt login code before saving to DB
        const encryptedLoginCode = cryptr.encrypt(loginCode.toString())

        let userToken = await Token.findOne({ userId: user._id })
        if (userToken) {
            await userToken.deleteOne()
        }

        // save token to db
        await new Token({
            userId: user._id,
            lToken: encryptedLoginCode,
            createdAt: Date.now(),
            expiresAt: Date.now() + 60 * (60 * 1000), // 60 minutes
        }).save()

        res.status(400)
        throw new Error("New device/browser detected. Check your email for email code")

    }


    // generate token
    const token = generateToken(user._id)

    if (user && passwordIsCorrect) {
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // id
            sameSite: "none",
            secure: true,
        });

        const { _id, name, email, phone, bio, photo, role, isVerified } = user

        res.status(200).json({
            _id, name, email, phone, bio, photo, role, isVerified, token
        })
    } else {
        res.status(500);
        throw new Error("Something went wrong, please try again!")
    }

})

const sendLoginCode = asyncHandler(async (req, res) => {
    const { email } = req.params
    const user = await User.findOne({ email });

    if (!user) {
        res.status(404)
        throw new Error("User not found");
    }

    // find login Code in DB
    let userToken = await Token.findOne({
        userId: user._id,
        expiresAt: { $gt: Date.now() }
    });

    if (!userToken) {
        res.status(404)
        throw new Error("Invalid or Expired token, Please login again!");
    }

    const loginCode = userToken.lToken;
    const decryptedLoginCode = cryptr.decrypt(loginCode)
    // send verification email
    const subject = "Login Access Code - Cotek"
    const send_to = email
    const send_from = process.env.SMTP_MAIL
    const reply_to = "noreply@cotek.com"
    const template = "loginCode"
    const name = user.name
    const link = decryptedLoginCode

    try {
        await sendEmail(subject, send_to, send_from, reply_to, template, name, link)
        res.status(200).json({ message: `Access Code sent to ${email}` })
    } catch (error) {
        console.error(error)
        res.status(500)
        throw new Error("Email not sent, please try again")
    }

});

// login with code
const loginWithCode = asyncHandler(async (req, res) => {
    const { email } = req.params
    const { loginCode } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
        res.status(404);
        throw new Error("User not found");
    }

    // find user login token
    const userToken = await Token.findOne({
        userId: user.id,
        expiresAt: { $gt: Date.now() }
    });

    if (!userToken) {
        res.status(404);
        throw new Error("Invalid or Expired Token, please login again");
    }

    const decryptedLoginCode = cryptr.decrypt(userToken.lToken);
    if (loginCode !== decryptedLoginCode) {
        res.status(400);
        throw new Error("Incorrect login code, please try again");
    } else {
        // register userAgent
        const ua = parser(req.headers["user-agent"]);
        const thisUserAgent = ua.ua;

        user.userAgent.push(thisUserAgent);

        await user.save()

        const token = generateToken(user._id)
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // id
            sameSite: "none",
            secure: true,
        })

        const { _id, name, email, phone, bio, photo, role, isVerified } = user

        res.status(200).json({
            _id, name, email, phone, bio, photo, role, isVerified, userAgent, token
        })
    }
})

// Logout
const logoutUser = asyncHandler(async (req, res) => {
    res.cookie("token", "", {
        path: "/",
        httpOnly: true,
        expires: new Date(0),
        sameSite: "none",
        secure: true,
    });
    return res.status(200).json({ message: "Logout successful" })
})

// get user
const getUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id)

    if (user) {
        const { _id, name, email, phone, bio, photo, role, isVerified } = user;
        res.status(200).json({
            _id,
            name,
            email,
            phone,
            bio,
            photo,
            role,
            isVerified,
        })
    } else {
        res.status(404);
        throw new Error("User not found")
    }
});

// update user
const updateUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id)

    if (user) {
        const { name, email, phone, bio, photo, role, isVerified } = user;

        user.email = email;
        user.name = req.body.name || name;
        user.phone = req.body.phone || phone;
        user.bio = req.body.bio || bio;
        user.photo = req.body.photo || photo;

        const updatedUser = await user.save()

        res.status(200).json({
            _id: updatedUser._id,
            name: updatedUser.name,
            email: updatedUser.email,
            phone: updatedUser.phone,
            bio: updatedUser.bio,
            photo: updatedUser.photo,
            role: updatedUser.role,
            isVerified: updatedUser.isVerified,
        })

    } else {
        res.status(404)
        throw new Error("User not found")
    }
});

// delete user
const deleteUser = asyncHandler(async (req, res) => {
    const user = User.findById(req.params.id)

    if (!user) {
        res.status(404)
        throw new Error("User not found")
    }

    await user.remove()
    res.status(200).json({ message: "User deleted successfully" })

})

// get users
const getUsers = asyncHandler(async (req, res) => {
    const users = await User.find().sort("-createdAt").select("-password")

    if (!users) {
        res.status(500)
        throw new Error("Something went wrong")
    }

    res.status(200).json(users);
})

// get login status
const loginStatus = asyncHandler(async (req, res) => {
    const token = req.cookies.token
    if (!token) {
        return res.json(false)
    }

    // Verify Token
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    if (verified) {
        return res.json(true);
    }

    return res.json(false)
})

// upgrade user
const upgradeUser = asyncHandler(async (req, res) => {
    const { role, id } = req.body
    const user = await User.findById(id)

    if (!user) {
        res.status(500)
        throw new Error("User not found")
    }

    user.role = role
    await user.save()

    res.status(200).json({ message: `User role updated to ${role}` })
})

const sendAutomatedEmail = asyncHandler(async (req, res) => {
    const { subject, send_to, reply_to, template, url } = req.body;

    if (!subject || !send_to || !reply_to || !template) {
        res.status(500)
        throw new Error("Missing email parameter")
    }

    // Get user
    const user = await User.findOne({ email: send_to })

    if (!user) {
        res.status(404)
        throw new Error("User not found")
    }

    const send_from = process.env.EMAIL_USER
    const name = user.name
    const link = `${process.env.FRONTEND_URL}${url}`

    try {
        await sendEmail(subject, send_to, send_from, reply_to, template, name, link)
        res.status(200).json({ message: "Email sent successfully" })
    } catch (error) {
        console.error(error)
        res.status(500)
        throw new Error("Email not sent, please try again")
    }
})

// forgot password
const forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body;

    const user = await User.findOne({ email })

    if (!user) {
        res.status(404)
        throw new Error("User with this email not found")
    }

    let token = await Token.findOne({ userId: user._id })
    if (token) {
        await token.deleteOne()
    }

    // Create Verfication Token and Save
    const resetToken = crypto.randomBytes(32).toString("hex") + user._id;
    console.log(resetToken)

    // Hash the token and save
    const hashedToken = hashToken(resetToken)
    await new Token({
        userId: user._id,
        rToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60 * 1000), // 60 minutes
    }).save()

    // construct verification url
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`

    // send verification email
    const subject = "Password Reset Request - Cotek"
    const send_to = user.email
    const send_from = process.env.SMTP_MAIL
    const reply_to = "noreply@cotek.com"
    const template = "forgotPassword"
    const name = user.name
    const link = resetUrl

    try {
        await sendEmail(subject, send_to, send_from, reply_to, template, name, link)
        res.status(200).json({ message: "Password Reset Email sent successfully" })
    } catch (error) {
        console.error(error)
        res.status(500)
        throw new Error("Email not sent, please try again")
    }
});

// Reset Password
const resetPassword = asyncHandler(async (req, res) => {
    const { resetToken } = req.params;
    const { password } = req.body;

    const hashedToken = hashToken(resetToken)

    const userToken = await Token.findOne({
        rToken: hashedToken,
        expiresAt: { $gt: Date.now() }
    })

    if (!userToken) {
        res.status(404);
        throw new Error("Invalid or Expired Token");
    }

    // Find User
    const user = await User.findOne({ _id: userToken.userId })

    // verify the user
    user.password = password;
    await user.save();

    res.status(200).json({ message: "Password Reset Successful, Please login" });
});

// change password
const changePassword = asyncHandler(async (req, res) => {
    const { oldPassword, password } = req.body
    const user = await User.findById(req.user._id);

    if (!user) {
        res.status(404);
        throw new Error("User not found");
    }

    if (!oldPassword || !password) {
        res.status(400);
        throw new Error("Please enter old and new password")
    }

    // check of old password is correct
    const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

    // Save new password
    if (user && passwordIsCorrect) {
        user.password = password;
        await user.save()
        res.status(200).json({ message: "Password change successful, Please re-login" })
    } else {
        res.status(400);
        throw new Error("Old password is incorrect")
    }

})

module.exports = {
    registerUser,
    loginUser,
    logoutUser,
    getUser,
    updateUser,
    deleteUser,
    getUsers,
    loginStatus,
    upgradeUser,
    sendAutomatedEmail,
    sendVerificationEmail,
    verifyUser,
    forgotPassword,
    resetPassword,
    changePassword,
    sendLoginCode,
    loginWithCode
}