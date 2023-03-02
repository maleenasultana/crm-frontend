//const cron = require("node-cron")
// // six stars each for sec,min,hour,day of month, month, day of week
// cron.schedule('*/5 * * * * *',() => console.log("please take care of your eyes"))

require("./crons/cron")

const dbConfig = require('./configs/db.config')
const mongoose = require('mongoose')
const express = require('express')

const app = express()
app.use(express.json())

mongoose.connect(dbConfig.DB_URL,
    () => {console.log("Connected to MongoDB")},
    err => { console.log("Error: " ,err.message)})

require('./routes/ticketNotification.route')(app)
 
app.listen(3030, () => {
    console.log("Application started on port 3030...")
})