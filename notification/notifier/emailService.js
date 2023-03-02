 const nodemailer = require("nodemailer")

module.exports = nodemailer.createTransport({
 
    service: "gmail",
    debug: true,
    auth: {
        user: 'maleenasultana@gmail.com',
        pass: 'qldyannjhdvoufrs'
    }
})

// const transporter = nodemailer.createTransport( {
//     service : "gmail",
//     auth : {
//         user: "maleenasultana@outlook.com",
//         pass: "Maleena321"
//     }
// });

// const options ={
//      from :"maleenasultana@outlook.com",
//      to: "maleenasultana@gmail.com",
//      subject :"Sending email with node",
//      text: "wooooow! sending emails with node  is actually that's so simple"
// };

// transporter.sendMail(options,function(err,info){
//     if(err){
//         console.log(err);
//         return
//     }
//     console.log("sent : ", info.response);
// })