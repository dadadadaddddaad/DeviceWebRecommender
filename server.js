// server-no-express.js
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const RSS = require('rss');
const fetch = require('node-fetch');
const cheerio = require('cheerio');

// Railway expune portul prin process.env.PORT
const PORT = process.env.PORT || 3000;
// Acest secret este folosit de server PENTRU A SEMNA PROPRIILE TOKEN-URI JWT pentru autentificarea userilor aplicației.
// Configurează-l ca variabilă de mediu pe Railway!
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key_12345';

// --- Supabase PostgreSQL Database Configuration (using Environment Variables) ---
const pool = new Pool({
  // !!! IMPORTANT PENTRU RAILWAY !!!
  // Configurează aceste variabile de mediu în Dashboard-ul Railway pentru Serviciul tău.
  // NU PUNE DATE SENSIBILE (PAROLA) DIRECT ÎN COD!
  // Mergi la Dashboard -> Project -> Serviciul tău -> Settings -> Environment Variables

  user: process.env.DB_USER || 'postgres', // Configurează variabila de mediu DB_USER (ex: postgres.wpbeibnkbpwbnvuaqssj)
  host: process.env.DB_HOST,             // Configurează variabila de mediu DB_HOST (hostname-ul Supabase)
  database: process.env.DB_NAME || 'postgres', // Configurează variabila de mediu DB_NAME
  password: process.env.DB_PASSWORD,         // <--- !!! Configurează variabila de mediu DB_PASSWORD cu PAROLA TA REALĂ !!!
  port: process.env.DB_PORT || 5432,         // Configurează variabila de mediu DB_PORT

  // Supabase necesită conexiune SSL
  ssl: {
      rejectUnauthorized: false // Setează true în producție dacă ai certificat valid, false pentru dezvoltare/hosting
  },

  // NOU: Forțează conexiunea să folosească doar IPv4 pentru a rezolva ENETUNREACH pe IPv6
  // Aceasta este cea mai probabilă soluție pentru eroarea pe care o primești pe platformele de hosting.
  family: 4
});

// Test database connection
pool.connect((err, client, done) => {
  if (err) {
    console.error('Database connection failed:', err.stack);
    console.error('DB Config used (without password):', {
        user: pool.options.user,
        host: pool.options.host,
        database: pool.options.database,
        port: pool.options.port,
        ssl_rejectUnauthorized: pool.options.ssl.rejectUnauthorized,
        family: pool.options.family, // Va afișa 4
    });
    console.error('Environment Variables check (password status):', {
        DB_USER_IS_SET: !!process.env.DB_USER,
        DB_HOST_IS_SET: !!process.env.DB_HOST,
        DB_NAME_IS_SET: !!process.env.DB_NAME,
        DB_PASSWORD_IS_SET: !!process.env.DB_PASSWORD, // TRUE if set, FALSE if not
        DB_PORT_IS_SET: !!process.env.DB_PORT,
        JWT_SECRET_IS_SET: !!process.env.JWT_SECRET,
        NODE_ENV: process.env.NODE_ENV,
    });

  } else {
    console.log('Successfully connected to the Supabase PostgreSQL database.');
    client.release();
  }
});

// --- Helper to send JSON responses ---
function sendJSON(res, data, status = 200) {
  if (res.headersSent) {
    console.warn('Attempted to send headers twice!');
    return;
  }
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' });
  res.end(JSON.stringify(data));
}

// --- Helper to parse request body for POST/PUT requests ---
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        if (body) {
             resolve(JSON.parse(body));
        } else {
             resolve({}); // Return empty object for empty body
        }
      } catch (e) {
          console.error("Failed to parse JSON body:", e);
          // Nu arunca eroare aici, returnează un obiect care indică eroarea de parcare
          resolve({ jsonError: e.message });
      }
    });
  });
}

// --- Helper to serve static files ---
function serveStatic(res, filePathRelative) {
   if (res.headersSent) {
        console.warn('Attempted to serve static file after headers sent!');
        return;
    }

   const baseDir = __dirname;
   let fullPath = path.join(baseDir, filePathRelative);

   if (filePathRelative === '/' || filePathRelative === 'index.html') {
        fullPath = path.join(baseDir, 'index.html');
   } else if (filePathRelative === 'product-details.html') {
        fullPath = path.join(baseDir, 'product-details.html');
   } else if (filePathRelative === 'favorites.html') {
        fullPath = path.join(baseDir, 'favorites.html');
   } else {
        fullPath = path.join(baseDir, filePathRelative);
   }


  fs.readFile(fullPath, (err, data) => {
    if (err) {
        // Loghează eroarea doar pentru fișierele așteptate, nu pentru 404 generale
        if (!['/favicon.ico'].includes(filePathRelative)) { // Ignoră favicon 404
             console.error(`Error reading static file ${fullPath}:`, err.message);
        }
         if (!res.headersSent) {
            res.writeHead(404, { 'Access-Control-Allow-Origin': '*' });
            res.end('Not found');
         }
    } else {
         if (!res.headersSent) {
            const ext = path.extname(fullPath);
            const contentType = {
                '.html': 'text/html',
                '.css': 'text/css',
                '.js': 'application/javascript',
                '.json': 'application/json',
                '.ico': 'image/x-icon',
                '.png': 'image/png',
                '.jpg': 'image/jpeg',
                '.gif': 'image/gif',
                '.svg': 'image/svg+xml',
                '.webmanifest': 'application/manifest+json'
            }[ext.toLowerCase()] || 'text/plain';
            res.writeHead(200, { 'Content-Type': contentType, 'Access-Control-Allow-Origin': '*' });
            res.end(data);
         }
    }
  });
}


// --- Middleware for authenticating JWT tokens ---
function authenticateToken(req, res, callback) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return sendJSON(res, { message: 'Acces refuzat. Niciun token furnizat.' }, 401);
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Verificarea tokenului a eșuat:', err.message);
      return sendJSON(res, { message: 'Token invalid sau expirat.' }, 403);
    }
    req.user = user;
    callback();
  });
}

// --- NOU: Funcție de scraping exemplu ---
async function scrapeProductPage(productUrl) {
    try {
        const response = await fetch(productUrl);
        const html = await response.text();
        const $ = cheerio.load(html);

        // ACESTA ESTE EXEMPLUL DE SELECTORI.
        // VEI TREBUI SĂ-I MODIFICI ÎN FUNCȚIE DE STRUCTURA HTML A SITE-URILOR PE CARE VREI SĂ LE SCRAPEZI.

        let name = $('h1.page-title').text().trim();
        // Compatibilitate extinsă pentru Optional Chaining
        if (!name) {
             const ogTitleMeta = $('meta[property="og:title"]');
             if (ogTitleMeta.length > 0) {
                 const ogTitleContent = ogTitleMeta.attr('content');
                 if (ogTitleContent) {
                     name = ogTitleContent.trim();
                 }
             }
        }


        let priceText = $('.product-price-now, .product-price span, .price').first().text().trim();
        if (!priceText) { // Fallback if common price selectors fail
            const dataPriceAttrElement = $('[data-price]').first();
            if (dataPriceAttrElement.length > 0) {
                 const dataPriceAttr = dataPriceAttrElement.attr('data-price');
                 if (dataPriceAttr) priceText = dataPriceAttr.trim();
            }
        }

        let price = null;
        if (priceText) {
            const cleanedPriceText = priceText.replace(/[^0-9.,]/g, '').replace(',', '.');
            price = parseFloat(cleanedPriceText);
        }
        price = isNaN(price) ? 0 : price;


        let batteryLife = null;
        $('p, li, span, div, td').each((i, el) => {
            const text = $(el).text().toLowerCase();
            const matchHours = text.match(/(\d+)\s*(ore|h)\b/);
            if (matchHours && matchHours[1]) {
                batteryLife = parseInt(matchHours[1], 10);
                return false;
            }
        });


        const features = [];
        $('.specs-list li, .features-list li, .description-content p, .product-attributes li, .details-section li').each((i, el) => {
            const featureText = $(el).text().trim();
            if (featureText.length > 5 && features.length < 15 && !features.includes(featureText) && !featureText.toLowerCase().includes('specificații generale')) {
                features.push(featureText);
            }
        });
         if (features.length < 5) {
             const pageText = $('body').text().toLowerCase();
             const keywords = ['5g', 'android', 'ios', 'bluetooth', 'wifi', 'gps', 'oled', 'amoled', 'lcd', 'rezistent la apă', 'dual sim', 'camera', 'procesor', 'gb ram', 'gb stocare', 'usb-c', 'nfc', 'jack 3.5mm', 'incarcare wireless'];
             keywords.forEach(keyword => {
                 if (pageText.includes(keyword) && features.length < 15) {
                     const displayKeyword = keyword.split(' ').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
                     if (!features.includes(displayKeyword)) {
                          features.push(displayKeyword);
                     }
                 }
             });
         }


        let type = null;
        const lowerUrl = productUrl.toLowerCase();
        if (lowerUrl.includes('telefon') || lowerUrl.includes('smartphone')) type = 'telefon';
        else if (lowerUrl.includes('tableta') || lowerUrl.includes('tablet')) type = 'tableta';
        else if (lowerUrl.includes('ceas') || lowerUrl.includes('smartwatch') || lowerUrl.includes('watch')) type = 'ceas';
        else if (lowerUrl.includes('drona') || lowerUrl.includes('drone')) type = 'drona';
        else if (lowerUrl.includes('laptop') || lowerUrl.includes('notebook')) type = 'laptop';
        else if (lowerUrl.includes('casti') || lowerUrl.includes('headphones') || lowerUrl.includes('earbuds')) type = 'casti';
        else {
             const lowerName = name ? name.toLowerCase() : '';
             if (lowerName.includes('telefon') || lowerName.includes('smartphone')) type = 'telefon';
             else if (lowerName.includes('tableta') || lowerName.includes('tablet')) type = 'tableta';
             else if (lowerName.includes('ceas') || lowerName.includes('smartwatch') || lowerName.includes('watch')) type = 'ceas';
             else if (lowerName.includes('drona') || lowerName.includes('drone')) type = 'drona';
             else if (lowerName.includes('laptop') || lowerName.includes('notebook')) type = 'laptop';
             else if (lowerName.includes('casti') || lowerName.includes('headphones') || lowerName.includes('earbuds')) type = 'casti';
        }
        type = type || 'necunoscut';

        let imageUrl = $('meta[property="og:image"]').attr('content');
        if (!imageUrl) imageUrl = $('img.product-main-image').attr('src');
        if (!imageUrl) imageUrl = $('img[itemprop="image"]').attr('src');
        if (!imageUrl) imageUrl = $('a.thumbnail img').attr('src');
        if (!imageUrl) imageUrl = $('img[alt*="' + (name || '').substring(0, 15) + '"]').attr('src');

        if (imageUrl && !imageUrl.startsWith('http')) {
            try {
                imageUrl = new URL(imageUrl, productUrl).href;
            } catch (e) {
                console.warn(`Could not resolve relative image URL: ${imageUrl}`);
                imageUrl = null;
            }
        } else if (imageUrl && imageUrl.startsWith('//')) {
             imageUrl = 'http:' + imageUrl;
        }
        if (imageUrl && (imageUrl.length < 15 || imageUrl.includes('data:image'))) {
            imageUrl = null;
        }


        return {
            name: name || 'Produs necunoscut',
            price: price,
            batterylife: batteryLife,
            type: type,
            features: features.length > 0 ? features : ['Caracteristici N/A'],
            link: productUrl,
            image: imageUrl || null
        };

    } catch (error) {
        console.error(`Eroare la scraping URL: ${productUrl}`, error.message);
        return { error: `Scraping failed for ${productUrl}: ${error.message}` };
    }
}


// Create the HTTP server
http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  let pathname = parsedUrl.pathname;
  const method = req.method; // Capturăm metoda HTTP

  // Logăm cererea primită pentru debugging
  console.log(`Received request: ${method} ${pathname}`);

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  // --- Static File Serving ---
   if (method === 'GET' && pathname !== '/rss' && !pathname.startsWith('/api/')) {
       // Asigură-te că serveStatic gestionează fișierele din rădăcină vs subdirectoare (ca 'public')
       // Rutăm '/' explicit la index.html
      return serveStatic(res, pathname === '/' ? 'index.html' : pathname.substring(1)); // Eliminăm slash-ul de la început pentru serveStatic
   }

   // Rută specifică pentru RSS (înainte de a verifica prefixul /api)
  if (method === 'GET' && pathname === '/rss') {
       console.log('Handling RSS feed request');
       try {
           const { limit } = parsedUrl.query;
           const queryLimit = (limit && parseInt(limit, 10) > 0) ? parseInt(limit, 10) : 100;

           let queryText = 'SELECT id, name, price, batterylife, type, features, link, created_at, image FROM products ORDER BY created_at DESC';
           const queryParams = [];

           if (queryLimit > 0) {
               queryText += ` LIMIT $1`;
               queryParams.push(queryLimit);
           }

           const { rows } = await pool.query(queryText, queryParams);

           const feed = new RSS({
             title: 'Ultimele Recomandări de Dispozitive Electronice',
             description: 'Cele mai recent adăugate dispozitive electronice',
             // Pe platforme de hosting, folosește hostname-ul real al aplicației
             feed_url: process.env.APP_BASE_URL ? `${process.env.APP_BASE_URL}/rss` : `http://localhost:${PORT}/rss`,
             site_url: process.env.APP_BASE_URL || `http://localhost:${PORT}`,
             language: 'ro'
           });

           rows.forEach(d => {
             const productDetailUrl = process.env.APP_BASE_URL
               ? `${process.env.APP_BASE_URL}/product-details.html?product_id=${d.id}`
               : `http://localhost:${PORT}/product-details.html?product_id=${d.id}`;

             feed.item({
               title: d.name,
               description: `Preț: ${d.price} Lei, Autonomie: ${d.batterylife ? d.batterylife + ' ore' : 'N/A'}, Tip: ${d.type}, Caracteristici: ${Array.isArray(d.features) ? d.features.join(', ') : 'N/A'}`,
               url: d.link && d.link !== 'null' && d.link.trim() !== '' ? d.link : productDetailUrl,
               date: d.created_at || new Date(),
               guid: d.id,
               enclosure: d.image ? { url: d.image, type: 'image/jpeg' } : undefined
             });
           });

           res.writeHead(200, { 'Content-Type': 'application/rss+xml', 'Access-Control-Allow-Origin': '*' });
           return res.end(feed.xml({ indent: true }));
       } catch (error) {
           console.error('Error generating RSS feed from DB:', error);
           return sendJSON(res, { message: 'Eroare la generarea feed-ului RSS.' }, 500);
       }
  }


  // --- API Endpoints ---
  // Rutăm toate cererile care încep cu '/api/'
  if (pathname.startsWith('/api/')) {
      // Rută: /api/recommendations (GET)
      if (method === 'GET' && pathname === '/api/recommendations') {
        console.log('Handling GET /api/recommendations');
        const { q = '', minPrice, maxPrice, batteryLife, deviceType } = parsedUrl.query;

        let queryText = 'SELECT id, name, price, batterylife, type, features, link, image FROM products WHERE 1=1';
        const queryParams = [];
        let paramIndex = 1;

        if (minPrice && parseFloat(minPrice) >= 0) {
            queryText += ` AND price >= $${paramIndex++}`;
            queryParams.push(parseFloat(minPrice));
        }
        if (maxPrice && parseFloat(maxPrice) >= 0) {
            queryText += ` AND price <= $${paramIndex++}`;
            queryParams.push(parseFloat(maxPrice));
        }
        if (batteryLife && parseInt(batteryLife, 10) >= 0) {
             queryText += ` AND batterylife >= $${paramIndex++}`;
             queryParams.push(parseInt(batteryLife, 10));
        }
        if (deviceType) {
            queryText += ` AND type = $${paramIndex++}`;
            queryParams.push(deviceType.toLowerCase());
        }

        if (q) {
            const searchTerm = `%${q.toLowerCase()}%`;
            queryText += ` AND (name ILIKE $${paramIndex++} OR EXISTS (SELECT 1 FROM UNNEST(features) AS feature WHERE feature ILIKE $${paramIndex++}) OR type ILIKE $${paramIndex++})`;
            queryParams.push(searchTerm, searchTerm, searchTerm);
        }

        queryText += ' ORDER BY id ASC';

        try {
            const { rows } = await pool.query(queryText, queryParams);
             const formattedRows = rows.map(row => ({
                 ...row,
                 features: Array.isArray(row.features) ? row.features : (typeof row.features === 'string' ? row.features.split(',').map(f => f.trim()).filter(f => f.length > 0) : [])
             }));
            return sendJSON(res, formattedRows);
        } catch (error) {
            console.error('Error fetching recommendations from DB:', error);
            return sendJSON(res, { message: 'Eroare la preluarea recomandărilor.', error: error.message }, 500);
        }
      }

      // Rută: /api/popular (GET)
      if (method === 'GET' && pathname === '/api/popular') {
          console.log('Handling GET /api/popular');
          try {
               const { rows } = await pool.query('SELECT id, name FROM products ORDER BY RANDOM() LIMIT 5');
               const popularItems = rows.map(row => ({ name: row.name, views: Math.floor(Math.random() * 100) + 50 }));

              return sendJSON(res, popularItems);
          } catch (error) {
              console.error('Error fetching popular stats:', error);
              return sendJSON(res, [], 500);
          }
      }

      // Rută: /api/register (POST)
      if (method === 'POST' && pathname === '/api/register') {
        console.log('Handling POST /api/register');
        try {
          const body = await parseBody(req);
           if (body.jsonError) {
              console.error('JSON parsing error:', body.jsonError);
              return sendJSON(res, { message: 'Invalid JSON body.', error: body.jsonError }, 400);
           }
           const { username, password, role } = body;


          if (!username || typeof username !== 'string' || username.trim() === '') {
             return sendJSON(res, { message: 'Numele de utilizator și parola sunt obligatorii.', field: 'username' }, 400);
           }

          const minLength = 6;
          const hasUppercase = /[A-Z]/.test(password);
          const hasDigit = /\d/.test(password);

          if (!password || typeof password !== 'string') {
               return sendJSON(res, { message: 'Parola este obligatorie.', field: 'password' }, 400);
          }

          if (password.length < minLength) {
            return sendJSON(res, { message: `Parola trebuie să aibă minim ${minLength} caractere.`, field: 'password' }, 400);
          }
          if (!hasUppercase) {
            return sendJSON(res, { message: 'Parola trebuie să conțină cel puțin o literă mare.', field: 'password' }, 400);
          }
          if (!hasDigit) {
            return sendJSON(res, { message: 'Parola trebuie să conțină cel puțin o cifră.', field: 'password' }, 400);
          }

          const userCheck = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
          if (userCheck.rows.length > 0) {
            return sendJSON(res, { message: 'Numele de utilizator există deja.', field: 'username' }, 409);
          }

          let finalRole = 'user';
          if (role === 'admin') {
              const adminCheck = await pool.query("SELECT COUNT(*) FROM users WHERE role = 'admin'");
              const adminCount = parseInt(adminCheck.rows[0].count, 10);
              if (adminCount === 0) {
                  finalRole = 'admin';
                  console.log(`Permitting first user "${username}" to register as admin.`);
              } else {
                  console.warn(`Attempted admin registration for "${username}" but admin already exists.`);
                  finalRole = 'user';
              }
          } else {
              finalRole = 'user';
          }


          const salt = await bcrypt.genSalt(10);
          const passwordHash = await bcrypt.hash(password, salt);

          const result = await pool.query(
            'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role',
            [username, passwordHash, finalRole]
          );

          const newUser = result.rows[0];
          const message = finalRole === 'admin'
            ? 'Utilizator admin înregistrat cu succes! (Sunteți primul admin)'
            : 'Utilizator înregistrat cu succes!';

          return sendJSON(res, { message: message }, 201);


        } catch (error) {
          console.error('Eroare la înregistrarea utilizatorului:', error.message, error.stack);
          if (error.code === '23505') {
              return sendJSON(res, { message: 'Numele de utilizator există deja.', field: 'username' }, 409);
          }
          return sendJSON(res, { message: 'Eroare de server la înregistrare.', error: error.message }, 500);
        }
      }

      // Rută: /api/login (POST)
      if (method === 'POST' && pathname === '/api/login') {
          console.log('Handling POST /api/login');
          try {
             const body = await parseBody(req);
             if (body.jsonError) {
                 console.error('JSON parsing error:', body.jsonError);
                 return sendJSON(res, { message: 'Invalid JSON body.', error: body.jsonError }, 400);
             }
             const { username, password } = body;


            if (!username || typeof username !== 'string' || username.trim() === '' || !password || typeof password !== 'string') {
                 return sendJSON(res, { message: 'Numele de utilizator și parola sunt obligatorii.' }, 400);
             }


            const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
            const user = result.rows[0];

            if (!user) {
              return sendJSON(res, { message: 'Nume de utilizator sau parolă incorecte.' }, 400);
            }

            const isMatch = await bcrypt.compare(password, user.password_hash);

            if (!isMatch) {
              return sendJSON(res, { message: 'Nume de utilizator sau parolă incorecte.' }, 400);
            }

            const token = jwt.sign(
              { userId: user.id, role: user.role, username: user.username },
              JWT_SECRET,
              { expiresIn: '15m' }
            );

            return sendJSON(res, { message: 'Conectat cu succes!', token, role: user.role, username: user.username });

          } catch (error) {
            console.error('Eroare la conectarea utilizatorului:', error.message, error.stack);
            return sendJSON(res, { message: 'Eroare de server la conectare.', error: error.message }, 500);
          }
      }


      // Rută: /api/products/:id (GET, PUT, DELETE)
      const productMatch = pathname.match(/^\/api\/products\/(\d+)$/);
      if (productMatch) {
          const productId = parseInt(productMatch[1], 10);
          console.log(`Handling ${method} /api/products/${productId}`);

           if (isNaN(productId)) {
               return sendJSON(res, { message: 'ID produs invalid.' }, 400);
           }

          if (method === 'GET') {
              // Get Single Product
              try {
                  const { rows } = await pool.query('SELECT id, name, price, batterylife, type, features, link, image FROM products WHERE id = $1', [productId]);
                  if (rows.length > 0) {
                      const product = rows[0];
                      product.features = Array.isArray(product.features) ? product.features : (typeof product.features === 'string' ? product.features.split(',').map(f => f.trim()).filter(f => f.length > 0) : []);
                      return sendJSON(res, product);
                  } else {
                      return sendJSON(res, { message: 'Produsul nu a fost găsit.' }, 404);
                  }
              } catch (error) {
                  console.error(`Error fetching product with ID ${productId} from DB:`, error);
                  return sendJSON(res, { message: 'Eroare la preluarea produsului.', error: error.message }, 500);
              }
          }

          if (method === 'PUT') {
              // Update Product (Admin only)
              return authenticateToken(req, res, async () => {
                if (req.user.role !== 'admin') {
                  return sendJSON(res, { message: 'Acces interzis. Doar administratorii pot edita produse.' }, 403);
                }

                try {
                  const body = await parseBody(req);
                   if (body.jsonError) {
                       console.error('JSON parsing error:', body.jsonError);
                       return sendJSON(res, { message: 'Invalid JSON body.', error: body.jsonError }, 400);
                   }
                  const { name, price, batteryLife, type, features, link, image } = body;


                   if (!name || typeof name !== 'string' || name.trim() === '' || isNaN(parseFloat(price)) || parseFloat(price) <= 0 || !type || typeof type !== 'string' || type.trim() === '' || !Array.isArray(features) || features.length === 0 || !features.every(f => typeof f === 'string' && f.trim().length > 0)) {
                        return sendJSON(res, { message: 'Datele produsului pentru actualizare sunt incomplete sau invalide.' }, 400);
                   }
                   const featuresArray = features.map(f => f.trim()).filter(f => f.length > 0); // Curățăm și validăm array-ul

                  const parsedBatteryLife = batteryLife ? parseInt(batteryLife, 10) : null;
                  const parsedLink = link && typeof link === 'string' && link.trim() !== '' ? link.trim() : null;
                  const parsedImage = image && typeof image === 'string' && image.trim() !== '' ? image.trim() : null;

                  const result = await pool.query(
                    'UPDATE products SET name = $1, price = $2, batterylife = $3, type = $4, features = $5, link = $6, image = $7 WHERE id = $8 RETURNING id, name',
                    [name.trim(), parseFloat(price), parsedBatteryLife, type.trim().toLowerCase(), featuresArray, parsedLink, parsedImage, productId]
                  );

                  if (result.rows.length > 0) {
                    console.log(`Product updated successfully: ${result.rows[0].name}`);
                    return sendJSON(res, { message: 'Produs actualizat cu succes!', product: result.rows[0] });
                  } else {
                    console.log(`Product ${productId} not found for update.`);
                    return sendJSON(res, { message: 'Produsul nu a fost găsit pentru actualizare.' }, 404);
                  }
                } catch (error) {
                  console.error('SERVER ERROR updating product:', error.message, error.stack);
                   return sendJSON(res, { message: 'Eroare de server la actualizarea produsului.', error: error.message }, 500);
                }
              });
          }

          if (method === 'DELETE') {
              // Delete Product (Admin only)
              return authenticateToken(req, res, async () => {
                if (req.user.role !== 'admin') {
                  return sendJSON(res, { message: 'Acces interzis. Doar administratorii pot șterge produse.' }, 403);
                }

                try {
                  const result = await pool.query('DELETE FROM products WHERE id = $1 RETURNING id', [productId]);
                  if (result.rows.length > 0) {
                    console.log(`Product ${productId} deleted successfully.`);
                    return sendJSON(res, { message: 'Produs șters cu succes!', id: result.rows[0].id });
                  } else {
                     console.log(`Product ${productId} not found for deletion.`);
                    return sendJSON(res, { message: 'Produsul nu a fost găsit pentru ștergere.' }, 404);
                  }
                } catch (error) {
                  console.error('SERVER ERROR deleting product:', error.message, error.stack);
                  return sendJSON(res, { message: 'Eroare de server la ștergerea produsului.', error: error.message }, 500);
                }
              });
          }

          // Dacă ID-ul de produs a fost match-uit, dar metoda nu este GET, PUT, sau DELETE
          return sendJSON(res, { message: `Metoda ${method} nu este permisă pentru /api/products/:id` }, 405);
      }

      // Rută: /api/products (POST) - Adaugă produs nou (Admin only)
      if (method === 'POST' && pathname === '/api/products') {
           console.log('Handling POST /api/products');
           return authenticateToken(req, res, async () => {
             if (req.user.role !== 'admin') {
               return sendJSON(res, { message: 'Acces interzis. Doar administratorii pot adăuga produse.' }, 403);
             }

             try {
               const body = await parseBody(req);
                if (body.jsonError) {
                    console.error('JSON parsing error:', body.jsonError);
                    return sendJSON(res, { message: 'Invalid JSON body.', error: body.jsonError }, 400);
                }
               const { name, price, batteryLife, type, features, link, image } = body;

               // Validări mai stricte
               if (!name || typeof name !== 'string' || name.trim() === '' || isNaN(parseFloat(price)) || parseFloat(price) <= 0 || !type || typeof type !== 'string' || type.trim() === '' || !Array.isArray(features) || features.length === 0 || !features.every(f => typeof f === 'string' && f.trim().length > 0)) {
                   return sendJSON(res, { message: 'Datele produsului pentru adăugare sunt incomplete sau invalide.' }, 400);
               }
                const featuresArray = features.map(f => f.trim()).filter(f => f.length > 0); // Curățăm și validăm array-ul

               const parsedBatteryLife = batteryLife ? parseInt(batteryLife, 10) : null;
               const parsedLink = link && typeof link === 'string' && link.trim() !== '' ? link.trim() : null;
               const parsedImage = image && typeof image === 'string' && image.trim() !== '' ? image.trim() : null;

               const result = await pool.query(
                 'INSERT INTO products (name, price, batterylife, type, features, link, image) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name',
                 [name.trim(), parseFloat(price), parsedBatteryLife, type.trim().toLowerCase(), featuresArray, parsedLink, parsedImage]
               );

               console.log(`Product added successfully: ${result.rows[0].name}`);

               return sendJSON(res, { message: 'Produs adăugat cu succes!', product: result.rows[0] }, 201);
             } catch (error) {
               console.error('SERVER ERROR adding product:', error.message, error.stack);
               return sendJSON(res, { message: 'Eroare de server la adăugarea produsului.', error: error.message }, 500);
             }
           });
      }


      // Rută: /api/favorites (POST, GET)
      if (pathname === '/api/favorites') {
           console.log(`Handling ${method} /api/favorites`);
           if (method === 'POST') {
               // Adaugă produs la favorite
               return authenticateToken(req, res, async () => {
                 const body = await parseBody(req);
                 if (body.jsonError) {
                     console.error('JSON parsing error:', body.jsonError);
                     return sendJSON(res, { message: 'Invalid JSON body.', error: body.jsonError }, 400);
                 }
                 const { productId } = body;
                 const userId = req.user.userId;

                 if (!productId) {
                   return sendJSON(res, { message: 'ID-ul produsului este obligatoriu.', field: 'productId' }, 400);
                 }

                 try {
                   const result = await pool.query(
                     'INSERT INTO user_favorites (user_id, product_id) VALUES ($1, $2) ON CONFLICT (user_id, product_id) DO NOTHING RETURNING *',
                     [userId, productId]
                   );

                   if (result.rowCount > 0) {
                     console.log(`Product ${productId} added to favorites for user ${userId}`);
                     return sendJSON(res, { message: 'Produs adăugat la favorite!', productId });
                   } else {
                     console.log(`Product ${productId} already in favorites for user ${userId} or not added.`);
                     return sendJSON(res, { message: 'Produsul este deja în favorite.' }, 409);
                   }
                 } catch (error) {
                   console.error('Eroare la adăugarea la favorite:', error);
                   return sendJSON(res, { message: 'Eroare de server la adăugarea la favorite.', error: error.message }, 500);
                 }
               });
           }
           if (method === 'GET') {
               // Preia lista de favorite a utilizatorului
               console.log('Handling GET /api/favorites');
               return authenticateToken(req, res, async () => {
                 const userId = req.user.userId;

                 try {
                   const { rows } = await pool.query(
                     `SELECT p.id, p.name, p.price, p.batterylife, p.type, p.features, p.link, p.image
                      FROM products p
                      JOIN user_favorites uf ON p.id = uf.product_id
                      WHERE uf.user_id = $1
                      ORDER BY uf.favorited_at DESC`,
                     [userId]
                   );
                   const formattedRows = rows.map(row => ({
                        ...row,
                        features: Array.isArray(row.features) ? row.features : (typeof row.features === 'string' ? row.features.split(',').map(f => f.trim()).filter(f => f.length > 0) : [])
                   }));
                   console.log(`Fetched ${formattedRows.length} favorites for user ${userId}`);
                   return sendJSON(res, formattedRows);
                 } catch (error) {
                   console.error('Eroare la preluarea listei de favorite:', error);
                   return sendJSON(res, { message: 'Eroare de server la preluarea favoritelor.', error: error.message }, 500);
                 }
               });
           }
            // Metodă nepermisă pentru /api/favorites
           return sendJSON(res, { message: `Metoda ${method} nu este permisă pentru /api/favorites` }, 405);
      }

      // Rută: /api/favorites/:productId (DELETE)
      if (method === 'DELETE' && pathname.startsWith('/api/favorites/')) {
           const productIdMatch = pathname.match(/^\/api\/favorites\/(\d+)$/);
            if (!productIdMatch) {
               // Acoperă cazul DELETE /api/favorites/ (fără ID) care altfel ar fi 404 mai jos
                if (pathname === '/api/favorites/') {
                    return sendJSON(res, { message: `Metoda ${method} nu este permisă pentru /api/favorites/ (adăugați ID-ul produsului)` }, 405);
                }
              // Altfel, ID-ul e invalid, cade mai jos la 404 sau la testul isNaN
            } else {
                 const productId = parseInt(productIdMatch[1], 10);
                 console.log(`Handling DELETE /api/favorites/${productId}`);

                 if (isNaN(productId)) {
                     return sendJSON(res, { message: 'ID produs invalid pentru eliminare favorit.' }, 400);
                 }

                 return authenticateToken(req, res, async () => {
                   const userId = req.user.userId;

                   try {
                     const result = await pool.query(
                       'DELETE FROM user_favorites WHERE user_id = $1 AND product_id = $2 RETURNING *',
                       [userId, productId]
                     );

                     if (result.rowCount > 0) {
                       console.log(`Product ${productId} removed from favorites for user ${userId}`);
                       return sendJSON(res, { message: 'Produs eliminat din favorite!', productId });
                     } else {
                        console.log(`Product ${productId} not found in favorites for user ${userId} or already removed.`);
                       return sendJSON(res, { message: 'Produsul nu a fost găsit în favorite.' }, 404);
                     }
                   } catch (error) {
                     console.error('Eroare la eliminarea din favorite:', error);
                     return sendJSON(res, { message: 'Eroare de server la eliminarea din favorite.', error: error.message }, 500);
                   }
                 });
            }
      }


      // Rută: /api/favorites/check/:productId (GET) - NU ESTE STRICT NECESAR, DAR PĂSTRĂM HANDLERUL
      if (method === 'GET' && pathname.startsWith('/api/favorites/check/')) {
         const productIdMatch = pathname.match(/^\/api\/favorites\/check\/(\d+)$/);
         if (!productIdMatch) {
            if (pathname === '/api/favorites/check/') {
                return sendJSON(res, { message: `ID produs lipsește pentru verificare favorit.` }, 400);
            }
             // Dacă path-ul începe dar nu se potrivește cu pattern-ul, cade mai jos la 404
         } else {
             const productId = parseInt(productIdMatch[1], 10);
             console.log(`Handling GET /api/favorites/check/${productId}`);

             if (isNaN(productId)) {
               return sendJSON(res, { message: 'ID produs invalid pentru verificare favorit.' }, 400);
             }

             return authenticateToken(req, res, async () => {
               const userId = req.user.userId;

               try {
                 const { rows } = await pool.query(
                   'SELECT 1 FROM user_favorites WHERE user_id = $1 AND product_id = $2',
                   [userId, productId]
                 );
                 console.log(`Checked favorite status for product ${productId} for user ${userId}: ${rows.length > 0}`);
                 return sendJSON(res, { isFavorited: rows.length > 0 });
               } catch (error) {
                 console.error('Eroare la verificarea favoritelor:', error);
                 return sendJSON(res, { message: 'Eroare de server la verificarea favoritelor.', error: error.message }, 500);
               }
             });
         }
      }


      // Rută: /api/scrape-product (POST) - Scraping (Admin only)
      if (method === 'POST' && pathname === '/api/scrape-product') {
          console.log('Handling POST /api/scrape-product');
          return authenticateToken(req, res, async () => {
              if (req.user.role !== 'admin') {
                  return sendJSON(res, { message: 'Acces interzis. Doar administratorii pot declanșa scraping-ul.' }, 403);
              }

              try {
                  const body = await parseBody(req);
                   if (body.jsonError) {
                       console.error('JSON parsing error:', body.jsonError);
                       return sendJSON(res, { message: 'Invalid JSON body.', error: body.jsonError }, 400);
                   }
                  const { url: productUrl } = body;

                  if (!productUrl || !productUrl.startsWith('http')) {
                      return sendJSON(res, { message: 'URL-ul produsului este invalid sau lipsește.' }, 400);
                  }

                  console.log(`Attempting to scrape URL: ${productUrl}`);
                  const scrapedData = await scrapeProductPage(productUrl);

                  if (!scrapedData || scrapedData.error) {
                      console.error('Scraping failed or returned error:', scrapedData ? scrapedData.error : 'No data');
                      return sendJSON(res, { message: scrapedData ? scrapedData.error : 'Nu s-au putut extrage date de pe URL-ul furnizat.', details: scrapedData }, 400);
                  }

                  if (!scrapedData.name || scrapedData.price === null || scrapedData.price <= 0 || !scrapedData.type || !Array.isArray(scrapedData.features) || scrapedData.features.length === 0) {
                       console.warn('Scraping returned incomplete or invalid data:', scrapedData);
                       return sendJSON(res, { message: 'Datele extrase din URL sunt incomplete (lipsesc nume, preț valid, tip sau caracteristici).', details: scrapedData }, 400);
                  }

                  const existingProduct = await pool.query('SELECT id FROM products WHERE link = $1', [scrapedData.link]);
                  if (existingProduct.rows.length > 0) {
                      console.log(`Product with link ${scrapedData.link} already exists.`);
                      return sendJSON(res, { message: 'Acest produs (cu acest link) există deja în baza de date.', product: existingProduct.rows[0] }, 409);
                  }

                   // Curăță caracteristicile înainte de inserare
                   const featuresToInsert = scrapedData.features.map(f => String(f).trim()).filter(f => f.length > 0);
                   if (featuresToInsert.length === 0) {
                       console.warn('Scraping returned features but they are empty after trimming:', scrapedData.features);
                       return sendJSON(res, { message: 'Caracteristicile extrase sunt goale sau invalide.', details: scrapedData }, 400);
                   }


                  const result = await pool.query(
                      'INSERT INTO products (name, price, batterylife, type, features, link, image) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name',
                      [scrapedData.name.trim(), scrapedData.price, scrapedData.batterylife, scrapedData.type.trim().toLowerCase(), featuresToInsert, scrapedData.link, scrapedData.image]
                  );

                  console.log(`Product scraped and added successfully: ${result.rows[0].name}`);
                  return sendJSON(res, { message: 'Produs scrapuit și adăugat cu succes!', product: result.rows[0] }, 201);

              } catch (error) {
                  console.error('SERVER ERROR during scraping/adding product:', error.message, error.stack);
                  return sendJSON(res, { message: 'Eroare de server la procesarea cererii de scraping.', error: error.message }, 500);
              }
          });
      }


      // Dacă path-ul începe cu /api/, dar nu s-a potrivit cu nicio rută specifică mai sus
      console.warn(`API route not found: ${method} ${pathname}`);
      return sendJSON(res, { message: `Ruta API ${method} ${pathname} nu a fost găsită.` }, 404);
  }


  // Dacă nicio rută (statică sau API) nu s-a potrivit
  console.warn(`No handler found for ${method} ${pathname}, returning 404`);
  res.writeHead(404, { 'Access-Control-Allow-Origin': '*' });
  res.end('Not found');

}).listen(PORT, () => console.log(`Server fără Express pornit pe http://localhost:${PORT}`));
