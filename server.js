// server-no-express.js
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const RSS = require('rss');
const fetch = require('node-fetch'); // Adaugă import pentru node-fetch
const cheerio = require('cheerio'); // Adaugă import pentru cheerio

const PORT = 3000;
// Acest secret este folosit de server PENTRU A SEMNA PROPRIILE TOKEN-URI JWT pentru autentificarea userilor aplicației.
// NU este cheia Anon sau Service Role de la Supabase pentru API, nici parola bazei de date.
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key_12345';

// --- Supabase PostgreSQL Database Configuration ---
const pool = new Pool({
  // !!! IMPORTANT !!!
  // Înlocuiește aceste valori cu credențialele REALE ALE BAZEI DE DATE de la Supabase.
  // Acestea le găsești în dashboard-ul Supabase, secțiunea:
  // Project Settings -> Database -> Connection string -> Node.js
  // Cheia 'anon' pe care ai furnizat-o NU este parola bazei de date.

  user: 'postgres', // De obicei este 'postgres'
  host: 'db.wpbeibnkbpwbnvuaqssj.supabase.co', // <--- FOLOSIM HOST-UL SPECIFICAT
  database: 'postgres', // De obicei este 'postgres'
  password: 'postgres', // <--- !!! ÎNLOCUIEȘTE ACEASTA CU PAROLA TA REALĂ A BAZEI DE DATE SUPABASE !!!
  port: 5432, // Default PostgreSQL port

  // Supabase necesită conexiune SSL
  ssl: {
      rejectUnauthorized: false // Setează true în producție dacă ai certificat, false pentru dezvoltare
  }
});

// Test database connection
pool.connect((err, client, done) => {
  if (err) {
    console.error('Database connection failed:', err.stack);
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
             resolve({});
        }
      } catch (e) {
          console.error("Failed to parse JSON body:", e);
          reject(new Error('Invalid JSON body'));
      }
    });
  });
}

// --- Helper to serve static files from 'public' directory ---
function serveStatic(res, pathname) {
   if (res.headersSent) {
        console.warn('Attempted to serve static file after headers sent!');
        return;
    }

  let filePath;
  if (pathname === '/') {
      filePath = path.join(__dirname, 'index.html');
  } else if (pathname === '/product-details.html') {
      filePath = path.join(__dirname, 'product-details.html');
  } else if (pathname === '/favorites.html') {
      filePath = path.join(__dirname, 'favorites.html');
  } else {
       filePath = path.join(__dirname, 'public', pathname);
       const rootFallbackPath = path.join(__dirname, pathname);
        if (!fs.existsSync(filePath) && fs.existsSync(rootFallbackPath)) {
             filePath = rootFallbackPath;
        }
  }

    const finalPath = filePath;

  fs.readFile(finalPath, (err, data) => {
    if (err) {
        console.error(`Error reading file ${finalPath}:`, err.message);
         if (!res.headersSent) {
            res.writeHead(404, { 'Access-Control-Allow-Origin': '*' });
            res.end('Not found');
         }
    } else {
         if (!res.headersSent) {
            const ext = path.extname(finalPath);
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
            }[ext] || 'text/plain';
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
        // Ex: pentru un produs de pe eMAG, Altex, Cel.ro etc.

        let name = $('h1.page-title').text().trim(); // Un selector comun pentru titlu
        if (!name) name = $('meta[property="og:title"]').attr('content')?.trim(); // Fallback pentru Open Graph title

        let priceText = $('.product-price-now').text().trim(); // Selector pentru preț
        if (!priceText) priceText = $('[data-price]').attr('data-price')?.trim(); // Alt posibil selector
        let price = priceText ? parseFloat(priceText.replace(/[^\d.,]/g, '').replace(',', '.')) : null;

        let batteryLife = null; // Va trebui să cauți cum e afișată autonomia bateriei
        // Exemplu: căutăm un paragraf sau li care conține "baterie" sau "autonomie"
        $('p, li, span, div').each((i, el) => { // Include div for broader search
            const text = $(el).text().toLowerCase();
            if (text.includes('baterie') || text.includes('autonomie')) {
                const match = text.match(/(\d+)\s*(ore|h)/); // Captures number followed by 'ore' or 'h'
                if (match && match[1]) {
                    batteryLife = parseInt(match[1], 10);
                    return false; // Ieșim din each odată ce găsim
                }
            }
             // Alternative: look for mAh values and try to estimate hours (more complex)
             if (!batteryLife && text.includes('mah')) {
                 const mahMatch = text.match(/(\d+)\s*mah/);
                 if (mahMatch && mahMatch[1]) {
                     const mah = parseInt(mahMatch[1], 10);
                     // Simple estimation: 1 hour per 200-300 mAh? Varies greatly.
                     // This is a very rough guess. Better to look for explicit hours.
                     if (mah > 0) {
                          // batteryLife = Math.round(mah / 250); // Example estimation
                          // For now, let's only rely on explicit hour mentions.
                     }
                 }
             }
        });


        // Caracteristicile sunt cel mai greu de scrapuit generic.
        // Aici vei dori probabil să cauți o listă de "specificații" sau "caracteristici"
        const features = [];
        // Look in common places for specs lists
        $('.specs-list li, .features-list li, .description-content p, .product-attributes li').each((i, el) => {
            const featureText = $(el).text().trim();
             // Avoid adding empty or very short items, limit total features
            if (featureText.length > 5 && features.length < 10 && !features.includes(featureText)) {
                features.push(featureText);
            }
        });
        // Fallback: search for common tech terms in the page text if no list found
        if (features.length === 0) {
             const pageText = $('body').text().toLowerCase();
             const keywords = ['5g', 'android', 'ios', 'bluetooth', 'wifi', 'gps', 'oled', 'amoled', 'lcd', 'rezistent la apă', 'dual sim', 'camera', 'procesor', 'gb ram', 'gb stocare']; // Add relevant keywords
             keywords.forEach(keyword => {
                 if (pageText.includes(keyword)) {
                      // Capitalize keywords for better display
                     const displayKeyword = keyword.split(' ').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
                     if (!features.includes(displayKeyword)) {
                          features.push(displayKeyword);
                     }
                 }
             });
        }


        // Tipul produsului ar putea fi inferat din URL sau din breadcrumbs
        let type = null;
        const lowerUrl = productUrl.toLowerCase();
        if (lowerUrl.includes('telefon') || lowerUrl.includes('smartphone')) type = 'telefon';
        else if (lowerUrl.includes('tableta') || lowerUrl.includes('tablet')) type = 'tableta';
        else if (lowerUrl.includes('ceas') || lowerUrl.includes('smartwatch') || lowerUrl.includes('watch')) type = 'ceas';
        else if (lowerUrl.includes('drona') || lowerUrl.includes('drone')) type = 'drona';
        else if (lowerUrl.includes('laptop') || lowerUrl.includes('notebook')) type = 'laptop';
        else if (lowerUrl.includes('casti') || lowerUrl.includes('headphones') || lowerUrl.includes('earbuds')) type = 'casti';
        else {
             // Attempt to guess from the name if available
             const lowerName = name ? name.toLowerCase() : '';
             if (lowerName.includes('telefon') || lowerName.includes('smartphone')) type = 'telefon';
             else if (lowerName.includes('tableta') || lowerName.includes('tablet')) type = 'tableta';
             else if (lowerName.includes('ceas') || lowerName.includes('smartwatch') || lowerName.includes('watch')) type = 'ceas';
             else if (lowerName.includes('drona') || lowerName.includes('drone')) type = 'drona';
             else if (lowerName.includes('laptop') || lowerName.includes('notebook')) type = 'laptop';
             else if (lowerName.includes('casti') || lowerName.includes('headphones') || lowerName.includes('earbuds')) type = 'casti';
        }
        type = type || 'necunoscut'; // Default if couldn't guess

        // Extract image URL
        let imageUrl = $('meta[property="og:image"]').attr('content');
        if (!imageUrl) {
            imageUrl = $('img.product-main-image').attr('src'); // Common image selector
        }
        if (!imageUrl) {
            imageUrl = $('img[itemprop="image"]').attr('src'); // Schema.org image selector
        }
        if (!imageUrl) {
             imageUrl = $('a.thumbnail img').attr('src'); // Example for thumbnail images
        }
         if (!imageUrl) {
             imageUrl = $('img[alt="' + name + '"]').attr('src'); // Try finding image by alt text
         }
        // Ensure the image URL is absolute
        if (imageUrl && !imageUrl.startsWith('http')) {
            try {
                imageUrl = new URL(imageUrl, productUrl).href;
            } catch (e) {
                console.warn(`Could not resolve relative image URL: ${imageUrl}`);
                imageUrl = null;
            }
        } else if (imageUrl && imageUrl.startsWith('//')) { // Handle protocol-relative URLs
             imageUrl = 'http:' + imageUrl; // Or 'https:'
        }


        // Returnează un obiect cu datele extrase
        return {
            name: name || 'Produs necunoscut',
            price: price || 0,
            batterylife: batteryLife,
            type: type,
            features: features.length > 0 ? features : ['Caracteristici N/A'],
            link: productUrl,
            image: imageUrl || null // Add the image URL here
        };

    } catch (error) {
        console.error(`Eroare la scraping URL: ${productUrl}`, error.message);
        return null;
    }
}


// Create the HTTP server
http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  let pathname = parsedUrl.pathname;

  // Handle CORS preflight requests
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  // --- Static File Serving ---
  if (req.method === 'GET' && !pathname.startsWith('/api') && pathname !== '/rss') {
      // Specific paths for root-level HTML files
      if (pathname === '/' || pathname === '/index.html') {
          return serveStatic(res, 'index.html');
      } else if (pathname === '/product-details.html') {
          return serveStatic(res, 'product-details.html');
      } else if (pathname === '/favorites.html') {
          return serveStatic(res, 'favorites.html');
      }
      // Serve other files from the root directory (CSS, JS, etc.)
      return serveStatic(res, pathname);
  }


  // --- API Endpoint: Device Recommendations ---
  if (req.method === 'GET' && pathname === '/api/recommendations') {
    const { q = '', minPrice, maxPrice, batteryLife, deviceType } = parsedUrl.query;

    let queryText = 'SELECT id, name, price, batterylife, type, features, link, image FROM products WHERE 1=1'; // Added 'image'
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
        queryParams.push(deviceType.toLowerCase()); // Store and search type as lowercase
    }

    if (q) {
        const searchTerm = `%${q.toLowerCase()}%`;
        queryText += ` AND (name ILIKE $${paramIndex++} OR EXISTS (SELECT 1 FROM UNNEST(features) AS feature WHERE feature ILIKE $${paramIndex++}) OR type ILIKE $${paramIndex++})`; // Search in name, features, AND type
        queryParams.push(searchTerm, searchTerm, searchTerm);
    }

    queryText += ' ORDER BY id ASC';

    try {
        const { rows } = await pool.query(queryText, queryParams);
         // Ensure features array is handled correctly if stored as string (though should be text[])
         const formattedRows = rows.map(row => ({
             ...row,
             features: Array.isArray(row.features) ? row.features : (typeof row.features === 'string' ? row.features.split(',').map(f => f.trim()).filter(f => f.length > 0) : [])
         }));
        return sendJSON(res, formattedRows);
    } catch (error) {
        console.error('Error fetching recommendations from DB:', error);
        return sendJSON(res, { message: 'Eroare la preluarea recomandărilor.' }, 500);
    }
  }

  // --- API Endpoint: Get Single Product by ID ---
  const productMatch = pathname.match(/^\/api\/products\/(\d+)$/);
  if (req.method === 'GET' && productMatch) {
    const productId = parseInt(productMatch[1], 10);
    if (isNaN(productId)) {
        return sendJSON(res, { message: 'ID produs invalid.' }, 400);
    }
    try {
        const { rows } = await pool.query('SELECT id, name, price, batterylife, type, features, link, image FROM products WHERE id = $1', [productId]); // Added 'image'
        if (rows.length > 0) {
             // Ensure features array is handled correctly
            const product = rows[0];
             product.features = Array.isArray(product.features) ? product.features : (typeof product.features === 'string' ? product.features.split(',').map(f => f.trim()).filter(f => f.length > 0) : []);
            return sendJSON(res, product);
        } else {
            return sendJSON(res, { message: 'Produsul nu a fost găsit.' }, 404);
        }
    } catch (error) {
        console.error(`Error fetching product with ID ${productId} from DB:`, error);
        return sendJSON(res, { message: 'Eroare la preluarea produsului.' }, 500);
    }
  }

  // --- API Endpoint: Add New Product (Admin only) ---
  if (req.method === 'POST' && pathname === '/api/products') {
    return authenticateToken(req, res, async () => {
      if (req.user.role !== 'admin') {
        return sendJSON(res, { message: 'Acces interzis. Doar administratorii pot adăuga produse.' }, 403);
      }

      try {
        const { name, price, batteryLife, type, features, link, image } = await parseBody(req); // Added 'image'

        if (!name || typeof name !== 'string' || name.trim() === '') {
            return sendJSON(res, { message: 'Numele produsului este obligatoriu.' }, 400);
        }
         const parsedPrice = parseFloat(price);
         if (isNaN(parsedPrice) || parsedPrice <= 0) {
             return sendJSON(res, { message: 'Prețul produsului trebuie să fie un număr pozitiv valid.' }, 400);
         }
         if (!type || typeof type !== 'string' || type.trim() === '') {
             return sendJSON(res, { message: 'Tipul produsului este obligatoriu.' }, 400);
         }
         const featuresArray = Array.isArray(features)
            ? features.map(f => String(f).trim()).filter(f => f.length > 0)
            : (typeof features === 'string' ? features.split(',').map(f => f.trim()).filter(f => f.length > 0) : []);
         if (featuresArray.length === 0) {
             return sendJSON(res, { message: 'Caracteristicile produsului sunt obligatorii (cel puțin una).' }, 400);
         }
        const parsedBatteryLife = batteryLife ? parseInt(batteryLife, 10) : null;
        const parsedLink = link && typeof link === 'string' && link.trim() !== '' ? link.trim() : null;
        const parsedImage = image && typeof image === 'string' && image.trim() !== '' ? image.trim() : null; // Handle image

        const result = await pool.query(
          'INSERT INTO products (name, price, batterylife, type, features, link, image) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name', // Added 'image'
          [name.trim(), parsedPrice, parsedBatteryLife, type.trim().toLowerCase(), featuresArray, parsedLink, parsedImage] // Store type as lowercase
        );
        return sendJSON(res, { message: 'Produs adăugat cu succes!', product: result.rows[0] }, 201);
      } catch (error) {
        console.error('SERVER ERROR adding product:', error.message, error.stack);
        return sendJSON(res, { message: 'Eroare de server la adăugarea produsului.', error: error.message }, 500);
      }
    });
  }

  // --- API Endpoint: Update Product (Admin only) ---
  const updateProductMatch = pathname.match(/^\/api\/products\/(\d+)$/);
  if (req.method === 'PUT' && updateProductMatch) {
    return authenticateToken(req, res, async () => {
      if (req.user.role !== 'admin') {
        return sendJSON(res, { message: 'Acces interzis. Doar administratorii pot edita produse.' }, 403);
      }

      const productId = parseInt(updateProductMatch[1], 10);
      if (isNaN(productId)) {
        return sendJSON(res, { message: 'ID produs invalid.' }, 400);
      }

      try {
        const { name, price, batteryLife, type, features, link, image } = await parseBody(req); // Added 'image'

         if (!name || typeof name !== 'string' || name.trim() === '') {
             return sendJSON(res, { message: 'Numele produsului este obligatoriu.' }, 400);
         }
          const parsedPrice = parseFloat(price);
          if (isNaN(parsedPrice) || parsedPrice <= 0) {
              return sendJSON(res, { message: 'Prețul produsului trebuie să fie un număr pozitiv valid.' }, 400);
          }
          if (!type || typeof type !== 'string' || type.trim() === '') {
              return sendJSON(res, { message: 'Tipul produsului este obligatoriu.' }, 400);
          }
          const featuresArray = Array.isArray(features)
             ? features.map(f => String(f).trim()).filter(f => f.length > 0)
             : (typeof features === 'string' ? features.split(',').map(f => f.trim()).filter(f => f.length > 0) : []);
          if (featuresArray.length === 0) {
              return sendJSON(res, { message: 'Caracteristicile produsului sunt obligatorii (cel puțin una).' }, 400);
          }
         const parsedBatteryLife = batteryLife ? parseInt(batteryLife, 10) : null;
         const parsedLink = link && typeof link === 'string' && link.trim() !== '' ? link.trim() : null;
         const parsedImage = image && typeof image === 'string' && image.trim() !== '' ? image.trim() : null; // Handle image

        const result = await pool.query(
          'UPDATE products SET name = $1, price = $2, batterylife = $3, type = $4, features = $5, link = $6, image = $7 WHERE id = $8 RETURNING id, name', // Added 'image'
          [name.trim(), parsedPrice, parsedBatteryLife, type.trim().toLowerCase(), featuresArray, parsedLink, parsedImage, productId] // Store type as lowercase
        );

        if (result.rows.length > 0) {
          return sendJSON(res, { message: 'Produs actualizat cu succes!', product: result.rows[0] });
        } else {
          return sendJSON(res, { message: 'Produsul nu a fost găsit pentru actualizare.' }, 404);
        }
      } catch (error) {
        console.error('SERVER ERROR updating product:', error.message, error.stack);
         return sendJSON(res, { message: 'Eroare de server la actualizarea produsului.', error: error.message }, 500);
      }
    });
  }

  // --- API Endpoint: Popular Statistics (Placeholder) ---
  // This endpoint is referenced in index.html but not implemented in the original server.js.
  // Adding a basic placeholder response. Real implementation would involve tracking views/clicks.
  if (req.method === 'GET' && pathname === '/api/popular') {
      try {
           // In a real app, query the DB for popular items based on views/clicks
           // Example: SELECT product_id, COUNT(*) as views FROM product_views GROUP BY product_id ORDER BY views DESC LIMIT 5;
           // For now, return dummy data or an empty array
           // Or, fetch top viewed products from the database if view tracking is implemented
           const { rows } = await pool.query('SELECT id, name FROM products ORDER BY RANDOM() LIMIT 5'); // Just fetch random products as a placeholder
           const popularItems = rows.map(row => ({ name: row.name, views: Math.floor(Math.random() * 100) + 50 })); // Add dummy view counts

           // If view tracking exists, replace the above dummy logic with real data query
           // const { rows: popularRows } = await pool.query(/* Your query for popular items */);
           // const popularItems = popularRows; // Assuming popularRows has { name, views } structure

          return sendJSON(res, popularItems); // Return the list of popular items
      } catch (error) {
          console.error('Error fetching popular stats:', error);
          // Fallback to an empty list or error message if DB query fails
          return sendJSON(res, [], 500); // Returning empty array might be safer than error
      }
  }


  // --- API Endpoint: RSS Feed ---
  if (req.method === 'GET' && pathname === '/rss') {
    try {
        const { limit } = parsedUrl.query;
        const queryLimit = (limit && parseInt(limit, 10) > 0) ? parseInt(limit, 10) : 100;

        let queryText = 'SELECT id, name, price, batterylife, type, features, link, created_at, image FROM products ORDER BY created_at DESC'; // Added 'image'
        const queryParams = [];

        if (queryLimit > 0) {
            queryText += ` LIMIT $1`;
            queryParams.push(queryLimit);
        }

        const { rows } = await pool.query(queryText, queryParams);

        const feed = new RSS({
          title: 'Ultimele Recomandări de Dispozitive Electronice',
          description: 'Cele mai recent adăugate dispozitive electronice',
          feed_url: `http://localhost:${PORT}/rss`,
          site_url: `http://localhost:${PORT}`,
          language: 'ro'
        });

        rows.forEach(d => {
          feed.item({
            title: d.name,
            description: `Preț: ${d.price} Lei, Autonomie: ${d.batterylife ? d.batterylife + ' ore' : 'N/A'}, Tip: ${d.type}, Caracteristici: ${Array.isArray(d.features) ? d.features.join(', ') : 'N/A'}`, // Ensure features is treated as array
            url: d.link && d.link !== 'null' && d.link.trim() !== '' ? d.link : `http://localhost:${PORT}/product-details.html?product_id=${d.id}`, // Link to product details page
            date: d.created_at || new Date(),
            guid: d.id,
            enclosure: d.image ? { url: d.image, type: 'image/jpeg' } : undefined // Add image to RSS feed
          });
        });

        res.writeHead(200, { 'Content-Type': 'application/rss+xml', 'Access-Control-Allow-Origin': '*' });
        return res.end(feed.xml({ indent: true }));
    } catch (error) {
        console.error('Error generating RSS feed from DB:', error);
        return sendJSON(res, { message: 'Eroare la generarea feed-ului RSS.' }, 500);
    }
  }

  // --- API Endpoint: User Registration ---
  if (req.method === 'POST' && pathname === '/api/register') {
    try {
      const { username, password, role } = await parseBody(req);

      if (!username || !password) {
        return sendJSON(res, { message: 'Numele de utilizator și parola sunt obligatorii.' }, 400);
      }

      const minLength = 6;
      const hasUppercase = /[A-Z]/.test(password);
      const hasDigit = /\d/.test(password);

      if (password.length < minLength) {
        return sendJSON(res, { message: `Parola trebuie să aibă minim ${minLength} caractere.` }, 400);
      }
      if (!hasUppercase) {
        return sendJSON(res, { message: 'Parola trebuie să conțină cel puțin o literă mare.' }, 400);
      }
      if (!hasDigit) {
        return sendJSON(res, { message: 'Parola trebuie să conțină cel puțin o cifră.' }, 400);
      }

      const userCheck = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
      if (userCheck.rows.length > 0) {
        return sendJSON(res, { message: 'Numele de utilizator există deja.' }, 409);
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
              finalRole = 'user'; // Force to user if admin already exists
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

      // Log in the user automatically after successful registration? Or require them to log in?
      // Let's not auto-login here, just confirm registration.
      return sendJSON(res, { message: message, user: { id: newUser.id, username: newUser.username, role: newUser.role } }, 201);

    } catch (error) {
      console.error('Eroare la înregistrarea utilizatorului:', error.message, error.stack);
      return sendJSON(res, { message: 'Eroare de server la înregistrare.', error: error.message }, 500);
    }
  }

  // --- API Endpoint: User Login ---
  if (req.method === 'POST' && pathname === '/api/login') {
    try {
      const { username, password } = await parseBody(req);

      if (!username || !password) {
        return sendJSON(res, { message: 'Numele de utilizator și parola sunt obligatorii.' }, 400);
      }

      const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
      const user = result.rows[0];

      if (!user) {
        return sendJSON(res, { message: 'Nume de utilizator sau parolă incorecte.' }, 400); // More generic message
      }

      const isMatch = await bcrypt.compare(password, user.password_hash);

      if (!isMatch) {
        return sendJSON(res, { message: 'Nume de utilizator sau parolă incorecte.' }, 400); // More generic message
      }

      const token = jwt.sign(
        { userId: user.id, role: user.role },
        JWT_SECRET,
        { expiresIn: '15m' } // Token expiration added for security
      );

      return sendJSON(res, { message: 'Conectat cu succes!', token, role: user.role, username: user.username });

    } catch (error) {
      console.error('Eroare la conectarea utilizatorului:', error.message, error.stack);
      return sendJSON(res, { message: 'Eroare de server la conectare.', error: error.message }, 500);
    }
  }

  // --- Protected API Endpoint (Example) ---
  // This endpoint is not used by the provided frontend code but remains for demonstration.
  if (req.method === 'GET' && pathname === '/api/protected-info') {
    return authenticateToken(req, res, async () => { // Changed to async to potentially fetch user details if needed
      // User is authenticated, req.user contains { userId, role }
      // If you need more user details here, you could fetch from DB:
      // const userResult = await pool.query('SELECT username FROM users WHERE id = $1', [req.user.userId]);
      // const username = userResult.rows[0]?.username || 'Unknown';
      if (req.user.role === 'admin') {
        return sendJSON(res, { message: `Bine ai venit, ${req.user.role}! Ai accesat informații protejate (admin). ID-ul tău: ${req.user.userId}.` });
      } else {
        return sendJSON(res, { message: `Bine ai venit, ${req.user.role}! Ai accesat informații protejate (user). ID-ul tău: ${req.user.userId}.` });
      }
    });
  }

  // --- API Endpoint pentru a adăuga un produs la favorite ---
  if (req.method === 'POST' && pathname === '/api/favorites') {
    return authenticateToken(req, res, async () => {
      const { productId } = await parseBody(req);
      const userId = req.user.userId;

      if (!productId) {
        return sendJSON(res, { message: 'ID-ul produsului este obligatoriu.' }, 400);
      }

      try {
        const result = await pool.query(
          'INSERT INTO user_favorites (user_id, product_id) VALUES ($1, $2) ON CONFLICT (user_id, product_id) DO NOTHING RETURNING *',
          [userId, productId]
        );

        if (result.rowCount > 0) {
          // Increment a favorite count for the product (optional, for popularity)
           // await pool.query('UPDATE products SET favorite_count = COALESCE(favorite_count, 0) + 1 WHERE id = $1', [productId]);
          return sendJSON(res, { message: 'Produs adăugat la favorite!', productId });
        } else {
          return sendJSON(res, { message: 'Produsul este deja în favorite.' }, 409); // Changed message
        }
      } catch (error) {
        console.error('Eroare la adăugarea la favorite:', error);
        return sendJSON(res, { message: 'Eroare de server la adăugarea la favorite.', error: error.message }, 500);
      }
    });
  }

  // --- API Endpoint pentru a elimina un produs din favorite ---
  if (req.method === 'DELETE' && pathname.startsWith('/api/favorites/')) {
    const productIdMatch = pathname.match(/\/api\/favorites\/(\d+)$/);
    if (!productIdMatch) {
      return sendJSON(res, { message: 'ID produs favorit invalid.' }, 400);
    }
    const productId = parseInt(productIdMatch[1], 10);

    return authenticateToken(req, res, async () => {
      const userId = req.user.userId;

      try {
        const result = await pool.query(
          'DELETE FROM user_favorites WHERE user_id = $1 AND product_id = $2 RETURNING *',
          [userId, productId]
        );

        if (result.rowCount > 0) {
           // Decrement the favorite count (optional)
           // await pool.query('UPDATE products SET favorite_count = GREATEST(0, COALESCE(favorite_count, 0) - 1) WHERE id = $1', [productId]);
          return sendJSON(res, { message: 'Produs eliminat din favorite!', productId });
        } else {
          return sendJSON(res, { message: 'Produsul nu a fost găsit în favorite.' }, 404); // Changed message
        }
      } catch (error) {
        console.error('Eroare la eliminarea din favorite:', error);
        return sendJSON(res, { message: 'Eroare de server la eliminarea din favorite.', error: error.message }, 500);
      }
    });
  }

  // --- API Endpoint pentru a prelua lista de favorite a utilizatorului ---
  if (req.method === 'GET' && pathname === '/api/favorites') {
    return authenticateToken(req, res, async () => {
      const userId = req.user.userId;

      try {
        const { rows } = await pool.query(
          `SELECT p.id, p.name, p.price, p.batterylife, p.type, p.features, p.link, p.image
           FROM products p
           JOIN user_favorites uf ON p.id = uf.product_id
           WHERE uf.user_id = $1
           ORDER BY uf.favorited_at DESC`, // Order by when it was favorited
          [userId]
        );
         // Ensure features array is handled correctly
        const formattedRows = rows.map(row => ({
             ...row,
             features: Array.isArray(row.features) ? row.features : (typeof row.features === 'string' ? row.features.split(',').map(f => f.trim()).filter(f => f.length > 0) : [])
        }));
        return sendJSON(res, formattedRows);
      } catch (error) {
        console.error('Eroare la preluarea listei de favorite:', error);
        return sendJSON(res, { message: 'Eroare de server la preluarea favoritelor.', error: error.message }, 500);
      }
    });
  }

  // --- API Endpoint pentru a verifica dacă un produs este în favoritele utilizatorului ---
  // This endpoint is not strictly needed with the /api/favorites endpoint that returns all favorites,
  // but keeping it for completeness if a frontend might need it.
  if (req.method === 'GET' && pathname.startsWith('/api/favorites/check/')) {
    const productIdMatch = pathname.match(/\/api\/favorites\/check\/(\d+)$/);
    if (!productIdMatch) {
      return sendJSON(res, { message: 'ID produs invalid pentru verificare favorite.' }, 400);
    }
    const productId = parseInt(productIdMatch[1], 10);

    return authenticateToken(req, res, async () => {
      const userId = req.user.userId;

      try {
        const { rows } = await pool.query(
          'SELECT 1 FROM user_favorites WHERE user_id = $1 AND product_id = $2',
          [userId, productId]
        );
        return sendJSON(res, { isFavorited: rows.length > 0 });
      } catch (error) {
        console.error('Eroare la verificarea favoritelor:', error);
        return sendJSON(res, { message: 'Eroare de server la verificarea favoritelor.', error: error.message }, 500);
      }
    });
  }


  // --- NOU: API Endpoint pentru a declanșa scraping-ul (Admin only) ---
  if (req.method === 'POST' && pathname === '/api/scrape-product') {
      return authenticateToken(req, res, async () => {
          if (req.user.role !== 'admin') {
              return sendJSON(res, { message: 'Acces interzis. Doar administratorii pot declanșa scraping-ul.' }, 403);
          }

          const { url: productUrl } = await parseBody(req);

          if (!productUrl || !productUrl.startsWith('http')) {
              return sendJSON(res, { message: 'URL-ul produsului este invalid sau lipsește.' }, 400);
          }

          try {
              const scrapedData = await scrapeProductPage(productUrl);

              if (!scrapedData || !scrapedData.name || scrapedData.price === null) {
                  return sendJSON(res, { message: 'Nu s-au putut extrage suficiente date de pe URL-ul furnizat. Verificați selectorii de scraping sau URL-ul.', details: scrapedData }, 400); // Include scraped data for debugging
              }

              // Verifică dacă un produs cu același link există deja pentru a evita duplicarea
              const existingProduct = await pool.query('SELECT id FROM products WHERE link = $1', [productUrl]);
              if (existingProduct.rows.length > 0) {
                  return sendJSON(res, { message: 'Acest produs (cu acest link) există deja în baza de date.', product: existingProduct.rows[0] }, 409);
              }

              // Inseră produsul scrapuit în baza de date
              const result = await pool.query(
                  'INSERT INTO products (name, price, batterylife, type, features, link, image) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name', // Added 'image'
                  [scrapedData.name, scrapedData.price, scrapedData.batterylife, scrapedData.type.toLowerCase(), scrapedData.features, scrapedData.link, scrapedData.image] // Store type as lowercase
              );

              return sendJSON(res, { message: 'Produs scrapuit și adăugat cu succes!', product: result.rows[0] }, 201);

          } catch (error) {
              console.error('SERVER ERROR during scraping/adding product:', error.message, error.stack);
              return sendJSON(res, { message: 'Eroare de server la procesarea cererii de scraping.', error: error.message }, 500);
          }
      });
  }


  // If no route matches
  res.writeHead(404, { 'Access-Control-Allow-Origin': '*' });
  res.end('Not found');

}).listen(PORT, () => console.log(`Server fără Express pornit pe http://localhost:${PORT}`));
