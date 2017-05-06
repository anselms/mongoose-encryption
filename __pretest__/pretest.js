var mongoose = require("mongoose");
var Mockgoose = require("mockgoose").Mockgoose;
var mockgoose = new Mockgoose(mongoose);

console.log("PRETEST: Preparing storage for mockgoose.");
mockgoose.prepareStorage().then(() => {
  process.exit(0);
});
