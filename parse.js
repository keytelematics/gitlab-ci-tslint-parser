#!/usr/bin/env node

var stdin = process.stdin;
var fs = require('fs');
var program = require('commander');
var version = require('./package.json').version;
var convert = require('./lib/convert.js')

var chunks = [];

program
  .version(version)
  .option('-o, --out <path>', 'output filename, defaults to gl-sast-report.json')
  .parse(process.argv);

var filename = program.out || 'gl-sast-report.json';

const inputJSON = fs.readFileSync("/dev/stdin", "utf-8");
const outputJSON = convert(inputJSON);

fs.writeFile(filename, outputJSON, function (err) {
  if (err) {
    return console.log(err);
  }

  console.log("The file was saved as " + filename + "!");
});


