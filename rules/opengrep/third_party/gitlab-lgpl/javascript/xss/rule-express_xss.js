// License: GNU Lesser General Public License v3.0
// source (original): https://github.com/ajinabraham/njsscan/blob/master/tests/assets/node_source/true_positives/semantic_grep/xss/xss_node.js
// hash: e7a0a61

// ok: rules_lgpl_javascript_xss_rule-express-xss
function someFunc(firstArg, secondArg) {someObject.write(firstArg)}


import express from "express";

const router = express.Router();

 // http://localhost:3000/xss/express/0?name=%3Cscript%3Ealert(%27Hi%27)%3C/script%3E
router.get('/0', (req, res) => {
    const { name } = req.query;
    var randomobj
    // ok: rules_lgpl_javascript_xss_rule-express-xss
    randomobj.send('<h1> Hello :' + name + '</h1>')
    // ruleid: rules_lgpl_javascript_xss_rule-express-xss
    res.send('<h1> Hello :' + name + '</h1>')
})

router.get("/", (req, res) => {
  const { name } = req.query
  // ruleid: rules_lgpl_javascript_xss_rule-express-xss
  return res.status(200).send({
    message: "Hello World!" + name,
  });
});

 // http://localhost:3000/xss/express/safe/1?name=%3Cscript%3Ealert(%27Hi%27)%3C/script%3E
router.get('/safe/0', (req, res) => {
    var name = req.query.name
    // ok: rules_lgpl_javascript_xss_rule-express-xss
    res.render('index', { title: name });
})

 // http://localhost:3000/xss/express/safe/1?name=%3Cscript%3Ealert(%27Hi%27)%3C/script%3E
router.get('/safe/1', (req, res) => {
    var name = encodeURI(req.query.name);
    // ok: rules_lgpl_javascript_xss_rule-express-xss
    res.send('index', { title: name });
})

export default router;

module.exports = function (app) {
    // http://localhost:3000/xss/express/1?name=%3Cscript%3Ealert(%27Hi%27)%3C/script%3E
    app.get('/xss/express/0', function (req, res) {
        var user = req.query.name;
        msg = "Hi " + user
        // ruleid:rules_lgpl_javascript_xss_rule-express-xss
        res.send('Response</br>' + msg);
    });

    // http://localhost:3000/xss/express/1?name=%3Cscript%3Ealert(%27Hi%27)%3C/script%3E
    app.get('/xss/express/1', function (req, res) {
        var user = req.query.name;
        var msg = [];
        msg.push(user);
        // ruleid:rules_lgpl_javascript_xss_rule-express-xss
        res.send('Response</br>' + msg[0]);
    });

    // http://localhost:3000/xss/express/2?name=%3Cscript%3Ealert(%27Hi%27)%3C/script%3E
    app.get('/xss/express/2', function (req, res) {
        var user = { user: req.query.name };
        console.log(user)
        // ruleid:rules_lgpl_javascript_xss_rule-express-xss
        res.send('Response</br>' + user.user);
    });

    var msg = '';
    // http://localhost:3000/xss/express/3?name=%3Cscript%3Ealert(%27Hi%27)%3C/script%3E
    app.get('/xss/express/3', function (req, res) {
        var user = req.query.name;
        msg = "Hi " + user
        // ruleid:rules_lgpl_javascript_xss_rule-express-xss
        res.send('Response</br>' + msg);
    });

    // http://localhost:3000/xss/express/4?name=%3Cscript%3Ealert(%27Hi%27)%3C/script%3E
    app.get('/xss/express/4', function (req, res) {
        var user = req.query.name;
        var header = "<html>";
        var msg = 'Hi ' + user;
        var footer = "</html>";
        var output = header + msg + footer;
        // ruleid:rules_lgpl_javascript_xss_rule-express-xss
        res.send(output);
    });

    // http://localhost:3000/xss/express/5?name=%3Cscript%3Ealert(%27Hi%27)%3C/script%3E
    app.get('/xss/express/5', function (req, res) {
        // ruleid:rules_lgpl_javascript_xss_rule-express-xss
        res.write( req.query['name']);
    });

    // http://localhost:3000/xss/express/6?name=%3Cscript%3Ealert(%27Hi%27)%3C/script%3E
    app.get('/xss/express/6', function (req, res) {
        // ruleid:rules_lgpl_javascript_xss_rule-express-xss
        res.write('Response</br>' + req.query.name);
    });
    
    // http://localhost:3000/xss/express/safe/1?name=%3Cscript%3Ealert(%27Hi%27)%3C/script%3E
    app.get('/xss/express/safe/1', function (req, res) {
        var resp = req.query.name;
        // ok:rules_lgpl_javascript_xss_rule-express-xss
        res.write('Response</br>');
    });

    // http://localhost:3000/xss/express/safe/2?name=%3Cscript%3Ealert(%27Hi%27)%3C/script%3E
    app.get('/xss/express/safe/2', function (req, res) {
        var foo = "foo";
        // ok:rules_lgpl_javascript_xss_rule-express-xss
        res.write('Response</br>' + foo);
    });

    // http://localhost:3000/xss/express/safe/3?name=%3Cscript%3Ealert(%27Hi%27)%3C/script%3E
    app.get('/xss/express/safe/3', function (req, res) {
        var user = encodeURI(req.query.name);
        msg = "Hi " + user;
         // ok:rules_lgpl_javascript_xss_rule-express-xss
        res.send('Response</br>' + msg);
    });

    // http://localhost:3000/xss/express/safe/3?name=%3Cscript%3Ealert(%27Hi%27)%3C/script%3E
    app.get('/xss/express/safe/4', function (req, res) {
        var user = req.query.name;
        var msg = [];
        msg.push(user);
        // ok: rules_lgpl_javascript_xss_rule-express-xss
        res.send('Response</br>' + encodeURI(msg[0]));
    });

    // http://localhost:3000/xss/express/safe/5?name=%3Cscript%3Ealert(%27Hi%27)%3C/script%3E
    app.get('/xss/express/safe/5', function (req, res) {
        var user = req.query.name;
        var msg = [];
        msg.push(user);
        // ok: rules_lgpl_javascript_xss_rule-express-xss
        res.send('Response</br>' + encodeURIComponent(msg[0]));
    });
}
