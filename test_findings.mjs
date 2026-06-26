import { chromium } from 'playwright';

(async () => {
  const browser = await chromium.launch();
  const context = await browser.createBrowserContext();
  const page = await context.newPage();

  try {
    // Navigate to the dashboard
    await page.goto('http://localhost:3000/dashboard', { waitUntil: 'networkidle', timeout: 15000 });
    console.log('✓ Navigated to dashboard');

    // Wait a bit for page to fully load
    await page.waitForLoadState('networkidle').catch(() => {});
    
    // Look for a scan link
    const scanLinks = await page.locator('a[href*="/scans/"]').first();
    const scanLink = await scanLinks.getAttribute('href').catch(() => null);
    
    if (scanLink) {
      console.log('✓ Found scan link:', scanLink);
      
      // Navigate to the first scan
      await page.goto(`http://localhost:3000${scanLink}`, { waitUntil: 'networkidle', timeout: 15000 });
      console.log('✓ Navigated to scan detail page');

      // Wait for findings section to be visible
      await page.waitForSelector('#scan-findings', { timeout: 5000 }).catch(() => {
        console.log('⚠ Findings section not found');
      });

      // Look for tab triggers (scanner tabs)
      await page.waitForTimeout(1000);
      const tabTriggers = await page.locator('[role="tab"]').all();
      
      if (tabTriggers.length > 0) {
        console.log(`✓ Found ${tabTriggers.length} tab triggers`);
        
        // Get text of first few tabs
        for (let i = 0; i < Math.min(3, tabTriggers.length); i++) {
          const text = await tabTriggers[i].textContent();
          console.log(`  Tab ${i + 1}:`, text.trim());
        }
      } else {
        console.log('⚠ No tab triggers found');
      }

      // Take a screenshot
      await page.screenshot({ path: '/tmp/findings_screenshot.png' });
      console.log('✓ Screenshot saved');
    } else {
      console.log('⚠ No scan links found');
    }
  } catch (error) {
    console.error('Error:', error.message);
  } finally {
    await browser.close();
  }
})();
