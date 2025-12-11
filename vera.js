// If the cloud says 'live', turn off test mode. Otherwise, keep it safe (true).
testMode: process.env.VERA_MODE !== 'live',// vera.js - The VERA Engine
require('dotenv').config();
const express = require('express');
const smartcar = require('smartcar');
const app = express();
const port = process.env.PORT || 8000;

app.set('view engine', 'ejs');
app.use(express.static('public'));

// 1. SMARTCAR CONFIGURATION (Using keys from .env)
const client = new smartcar.AuthClient({
  clientId: process.env.SMARTCAR_CLIENT_ID,
  clientSecret: process.env.SMARTCAR_CLIENT_SECRET,
  redirectUri: process.env.SMARTCAR_REDIRECT_URI,
  // Define all necessary scopes for the forensic scan
  scope: [
    'read_vehicle_info', 'read_odometer', 'read_engine_oil', 
    'read_tires', 'read_battery', 'read_vin'
  ],
  testMode: true, // IMPORTANT: Use testMode for development and demo
});

// Helper Function: The VERA Risk Algorithm
function calculateVeraScore(data) {
  let score = 100;
  let deductions = [];

  // Odometer Risk (>80k miles)
  if (data.odometer && data.odometer.distance > 80000) { 
      score -= 15; 
      deductions.push("High Mileage Risk (>80k)");
  }

  // Oil Life Risk (Critical for neglect assessment)
  if (data.oil && data.oil.lifeRemaining < 0.20) { 
      score -= 25; 
      deductions.push("CRITICAL: Oil Service Required (<20% Life)"); 
  }

  // Tire Pressure Risk (If any tire is significantly low)
  if (data.tires) {
      const pressures = [data.tires.frontLeft, data.tires.frontRight, data.tires.backLeft, data.tires.backRight];
      if (pressures.some(p => p < 28)) { // 28 PSI as a low threshold
          score -= 10;
          deductions.push("Tire Pressure Anomaly Detected");
      }
  }

  return { 
      score: Math.max(0, score), 
      deductions: deductions,
      status: score > 75 ? "PASSED" : "REVIEW REQUIRED"
  };
}

// 2. ROUTE: LOGIN PAGE
app.get('/', (req, res) => {
  const authUrl = client.getAuthUrl();
  res.render('index', { authUrl });
});

// 3. ROUTE: THE HANDSHAKE (Callback)
app.get('/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.send("Error: No code returned.");

  try {
    const access = await client.exchangeCode(code);
    const vehicles = await smartcar.getVehicles(access.accessToken);
    const vehicle = new smartcar.Vehicle(vehicles.vehicles[0], access.accessToken);

    // PARALLEL SCAN (Fetch all data simultaneously)
    const [attributes, odometer, oil, tires, battery] = await Promise.all([
      vehicle.attributes().catch(e => null),
      vehicle.odometer().catch(e => null),
      vehicle.oilLife().catch(e => null),
      vehicle.tirePressure().catch(e => null),
      vehicle.battery().catch(e => null)
    ]);

    // Calculate Score
    const audit = calculateVeraScore({ attributes, odometer, oil, tires, battery });

    // Render the final Certificate
    res.render('certificate', { 
        vehicle: attributes, 
        data: { odometer, oil, tires, battery }, 
        audit 
    });

  } catch (err) {
    console.error("\nVERA SYSTEM ERROR:", err);
    res.send("<h1>VERA Connection Failed.</h1><p>Check the terminal for the error details.</p>");
  }
});

// Start Server
app.listen(port, () => {
  console.log(`VERA Engine Online: http://localhost:${port}`);
  console.log("--- Ready for Digital Handshake ---");
});
