'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');

// ---- Middleware ----
app.use(express.json());
app.use(express.static(__dirname));

// ---- Helper functions ----

function dataFile(name) {
    return path.join(DATA_DIR, name + '.json');
}

function readData(name) {
    const file = dataFile(name);
    if (!fs.existsSync(file)) return [];
    return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeData(name, data) {
    fs.writeFileSync(dataFile(name), JSON.stringify(data, null, 2), 'utf8');
}

function nextId(items) {
    if (items.length === 0) return 1;
    return Math.max(...items.map(i => i.id)) + 1;
}

// ---- Generic CRUD factory ----

function crudRouter(name) {
    const router = express.Router();

    // GET all
    router.get('/', (req, res) => {
        res.json(readData(name));
    });

    // GET one
    router.get('/:id', (req, res) => {
        const items = readData(name);
        const item = items.find(i => i.id === parseInt(req.params.id, 10));
        if (!item) return res.status(404).json({ error: 'Not found' });
        res.json(item);
    });

    // POST create
    router.post('/', (req, res) => {
        const items = readData(name);
        const newItem = { id: nextId(items), ...req.body };
        items.push(newItem);
        writeData(name, items);
        res.status(201).json(newItem);
    });

    // PUT update
    router.put('/:id', (req, res) => {
        const items = readData(name);
        const idx = items.findIndex(i => i.id === parseInt(req.params.id, 10));
        if (idx === -1) return res.status(404).json({ error: 'Not found' });
        items[idx] = { id: items[idx].id, ...req.body };
        writeData(name, items);
        res.json(items[idx]);
    });

    // DELETE
    router.delete('/:id', (req, res) => {
        const items = readData(name);
        const idx = items.findIndex(i => i.id === parseInt(req.params.id, 10));
        if (idx === -1) return res.status(404).json({ error: 'Not found' });
        items.splice(idx, 1);
        writeData(name, items);
        res.json({ ok: true });
    });

    return router;
}

// ---- API routes ----
app.use('/api/incidents', crudRouter('incidents'));
app.use('/api/resources', crudRouter('resources'));
app.use('/api/users', crudRouter('users'));

// ---- Start ----
app.listen(PORT, () => {
    console.log('Сервер запущен: http://localhost:' + PORT);
});
