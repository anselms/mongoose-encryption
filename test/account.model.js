
var mongoose = require("mongoose");
var encrypt = require("../index");

var Schema = mongoose.Schema;
mongoose.set("debug", true);


// *** BASE SCHEMA *** //

var AccountSchema = new Schema(
  {
    userId: {
      type: Schema.Types.ObjectId,
      index: true,
      unique: false,
      required: true
    },
    bankID: Schema.Types.ObjectId,
    name: String,
    number: Number,
    blz: Number,
    bankName: String
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

// *** HELPERS *** //


// *** MIDDLEWARE *** //



AccountSchema.plugin(encrypt, {
  excludeFromEncryption: ["userId", "bankID", "status"],
  idForKey : "userId"
//  encryptedFields : ['blz']
});





// *** SETTINGS *** //
AccountSchema.set("toJSON", { getters: true, setters: true, virtuals: true });

// *** IMPLEMENT *** //

mongoose.model("Account", AccountSchema);
