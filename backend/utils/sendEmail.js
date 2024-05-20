const nodemailer = require("nodemailer");
const hbs = require("nodemailer-express-handlebars");
const path = require("path");

const sendEmail = async (subject, send_to, send_from, reply_to, template, name, link) => {
    // Create Email Transporter
    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: 465,
        auth: {
            user: process.env.SMTP_MAIL,
            pass: process.env.SMTP_PASSWORD,
        },
        tls: {
            rejectUnauthorized: false
        }
    })

    const handlerOptions = {
        viewEngine: {
            extName: ".handlebars",
            partialsDir: path.resolve("./views"),
            defaultLayout: false
        },
        viewPath: path.resolve("./views"),
        extName: ".handlebars"
    }

    transporter.use("compile", hbs(handlerOptions));

    // options for sending email
    const options = {
        from: send_from,
        to: send_to,
        replyTo: reply_to,
        subject,
        template,
        context: {
            name, 
            link,
        }
    }

    // Send email
    transporter.sendMail(options, function(err, info) {
        if (err) {
            console.log(err)
        } else {
            console.log(info)
        }
    })

};

module.exports = sendEmail;
