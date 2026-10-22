StockFlow landing-page update

Replace the repository files with the contents of this ZIP while preserving the included structure.

Important paths:
- server.js
- smtp.js
- public/index.html       Public landing/login page
- public/auth.html        Dedicated login/register/reset page
- public/dashboard.html   Existing StockFlow inventory dashboard (preserved from prior index.html)
- public/stockflow-hero.jpg
- public/favicon.svg
- public/manifest.webmanifest

After uploading to GitHub, commit and push. Render should redeploy from the configured branch.

Testing completed: Node syntax checks passed for server.js, smtp.js, and inline scripts in all three HTML pages. This is not a full browser or live deployment test. Render database persistence and email configuration remain separate items to verify.
