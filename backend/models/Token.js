const mongoose = require('mongoose');

const tokenSchema = mongoose.Schema(
    {
        vToken: {
            type: String,
            default: "",
        },
        rToken: {
            type: String,
            default: "",
        },
        lToken: {
            type: String,
            default: "",
        },
        createdAt: {
            type: Date,
            required: true,
        },
        expiresAt: {
            type: Date,
            required: true,
        },
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            required: true,
            ref: 'user',
        },
    },
);



const Token = mongoose.model("Token", tokenSchema);
module.exports = Token;