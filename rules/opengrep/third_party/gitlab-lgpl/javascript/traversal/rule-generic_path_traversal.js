// License: GNU Lesser General Public License v3.0
// source (original): https://github.com/ajinabraham/njsscan/blob/master/tests/assets/node_source/true_positives/semantic_grep/traversal/path_traversal.js
// hash: e7a0a61
var fileSystem = require('fs'),
    path = require('path')
    http = require('http');

var Promise = require('bluebird');
Promise.promisifyAll(fileSystem);

module.exports = function (app) {
    // http://localhost:3000/traversal/generic-path-traversal/1?load=../../assets/xml/xxe_xml.xml
    app.get('/traversal/generic-path-traversal/1', function (req, res) {
        var filePath = path.join(__dirname, '/' + req.query.load);

        // ruleid:rules_lgpl_javascript_traversal_rule-generic-path-traversal
        var readStream = fileSystem.createReadStream(filePath);

        // ruleid:rules_lgpl_javascript_traversal_rule-generic-path-traversal
        fileSystem.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                console.error('Error reading file:', err);
                return;
            }
            console.log('File contents:', data);
        });
        readStream.pipe(res);
    });

     // http://localhost:3000/traversal/generic-path-traversal/2?load=books.xml
     app.get('/traversal/generic-path-traversal/2', function (req, res) {
        // ruleid:rules_lgpl_javascript_traversal_rule-generic-path-traversal
        fileSystem.readFile(req.query.load, 'utf8', (err, data) => {
            if (err) {
                console.error('Error:', err);
                res.send(500)
            }
            console.log('content', data);
        });
    });

    // http://localhost:3000/traversal/generic-path-traversal/3?load=books.xml
    app.get('/traversal/generic-path-traversal/3', async function (req, res) {
        // ruleid:rules_lgpl_javascript_traversal_rule-generic-path-traversal
        console.log( await fileSystem.readFileSync(req.query.load, 'utf8'));
    });

    // http://localhost:3000/traversal/generic-path-traversal/4?load=../../books.xml
    app.get('/traversal/generic-path-traversal/4', async function (req, res) {
        var filePath = path.join(__dirname, '/' + req.query.load);
        // ruleid:rules_lgpl_javascript_traversal_rule-generic-path-traversal
        console.log( await fileSystem.readFileSync(filePath, 'utf8'));
    });

    // http://localhost:3000/traversal/generic-path-traversal/5?load=../../books.xml
    app.get('/traversal/generic-path-traversal/5', function (req, res) {
    var load = req.query.load;
    var fileName = __dirname+ '/' + load;
    var downloadFileName = 'books.xml';

    // ruleid:rules_lgpl_javascript_traversal_rule-generic-path-traversal
    fileSystem.readFileAsync(req.query.load)
        .then(function (data) {
            console.log(data)
            res.download(fileName, downloadFileName);
        })
    })

    // http://localhost:3000/traversal/generic-path-traversal/safe/1
    app.get('/traversal/generic-path-traversal/safe/1', function (req, res) {
        var filePath = path.join(__dirname, process.env.FULLFILEPATH);

        // ok:rules_lgpl_javascript_traversal_rule-generic-path-traversal
        var readStream = fileSystem.createReadStream(filePath);

        // ok:rules_lgpl_javascript_traversal_rule-generic-path-traversal
        fileSystem.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                // console.error('Error reading file:', err);
                // return;
            }
            // console.log('File contents:', data);
        });
        readStream.pipe(res);
    });
}