// LandingPage.jsx
import React from 'react';
import { Shield, Upload, Download, CheckCircle, Zap, Lock, FileText, ArrowRight, Star } from 'lucide-react';
import styles from './LandingPage.module.css';

const LandingPage = () => {
  return (
    <div className={styles.landingPage}>
      {/* Hero Section */}
      <section className={styles.hero}>
        <div className={styles.container}>
          <div className={styles.heroContent}>
            <div className={styles.heroIcon}>
              <Shield size={64} />
            </div>
            <h1 className={styles.heroTitle}>
              Certificate Validation & Conversion
              <span className={styles.heroSubtitle}>Made Simple</span>
            </h1>
            <p className={styles.heroDescription}>
              Stop wrestling with cryptic OpenSSL errors. Upload, validate, convert, and download your certificates in any format you need - all in seconds, completely free.
            </p>
            <div className={styles.heroButtons}>
              <button 
                className={styles.primaryButton}
                onClick={() => window.location.href = '/app'}
              >
                <Upload size={20} />
                Start Analyzing Certificates
              </button>
              <button className={styles.secondaryButton}>
                <FileText size={20} />
                View Documentation
              </button>
            </div>
            <div className={styles.heroFeatures}>
              <div className={styles.heroFeature}>
                <CheckCircle size={16} />
                <span>100% Free</span>
              </div>
              <div className={styles.heroFeature}>
                <CheckCircle size={16} />
                <span>No Registration</span>
              </div>
              <div className={styles.heroFeature}>
                <CheckCircle size={16} />
                <span>Privacy First</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Problems Section */}
      <section className={styles.problems}>
        <div className={styles.container}>
          <h2 className={styles.sectionTitle}>Tired of Certificate Headaches?</h2>
          <div className={styles.problemGrid}>
            <div className={styles.problemCard}>
              <div className={styles.problemIcon}>😤</div>
              <h3>Cryptic Error Messages</h3>
              <p>"unable to get local issuer certificate" - What does that even mean? Debugging SSL issues shouldn't require a PhD in cryptography.</p>
            </div>
            <div className={styles.problemCard}>
              <div className={styles.problemIcon}>🔄</div>
              <h3>Format Conversion Hell</h3>
              <p>Need PEM but have P12? Want DER from PFX? Converting between certificate formats with OpenSSL is a nightmare of complex commands.</p>
            </div>
            <div className={styles.problemCard}>
              <div className={styles.problemIcon}>🤯</div>
              <h3>Chain Building Confusion</h3>
              <p>Which certificate goes where? Manually ordering certificate chains is error-prone and frustrating for even experienced developers.</p>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className={styles.features}>
        <div className={styles.container}>
          <h2 className={styles.sectionTitle}>Everything You Need in One Tool</h2>
          <div className={styles.featureGrid}>
            <div className={styles.featureCard}>
              <div className={styles.featureIcon}>
                <Zap />
              </div>
              <h3>Instant Validation</h3>
              <p>Upload certificates and get validation results in seconds. See exactly what's valid, what's broken, and how to fix it.</p>
            </div>
            <div className={styles.featureCard}>
              <div className={styles.featureIcon}>
                <Download />
              </div>
              <h3>Format Conversion</h3>
              <p>Convert between PEM, DER, P12, PFX formats instantly. No more wrestling with OpenSSL command syntax.</p>
            </div>
            <div className={styles.featureCard}>
              <div className={styles.featureIcon}>
                <Shield />
              </div>
              <h3>Smart Chain Building</h3>
              <p>Automatically detects and builds complete certificate chains. Download properly ordered PKI bundles.</p>
            </div>
            <div className={styles.featureCard}>
              <div className={styles.featureIcon}>
                <Lock />
              </div>
              <h3>Secure & Private</h3>
              <p>Session-based processing. Your certificates are never stored permanently on our servers.</p>
            </div>
            <div className={styles.featureCard}>
              <div className={styles.featureIcon}>
                <FileText />
              </div>
              <h3>Multiple Formats</h3>
              <p>Supports PEM, DER, P12/PFX, CSR, and private key files. Just drag and drop any certificate format.</p>
            </div>
            <div className={styles.featureCard}>
              <div className={styles.featureIcon}>
                <Star />
              </div>
              <h3>Educational</h3>
              <p>Learn PKI concepts visually. Perfect for understanding certificate relationships and hierarchies.</p>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className={styles.howItWorks}>
        <div className={styles.container}>
          <h2 className={styles.sectionTitle}>How It Works</h2>
          <p className={styles.sectionSubtitle}>Three simple steps to certificate clarity</p>
          
          <div className={styles.stepsGrid}>
            <div className={styles.step}>
              <div className={styles.stepNumber}>1</div>
              <div className={styles.stepContent}>
                <h3>Upload & Analyze</h3>
                <p>Drag and drop your certificate files. We support .pem, .crt, .der, .p12, .pfx, .key, and .csr files. Get instant validation results.</p>
              </div>
            </div>
            <div className={styles.stepArrow}>
              <ArrowRight size={24} />
            </div>
            <div className={styles.step}>
              <div className={styles.stepNumber}>2</div>
              <div className={styles.stepContent}>
                <h3>Convert & Build</h3>
                <p>Convert to any format you need. Automatically build complete certificate chains with proper ordering from end-entity to root.</p>
              </div>
            </div>
            <div className={styles.stepArrow}>
              <ArrowRight size={24} />
            </div>
            <div className={styles.step}>
              <div className={styles.stepNumber}>3</div>
              <div className={styles.stepContent}>
                <h3>Download & Deploy</h3>
                <p>Download properly formatted certificates, complete PKI bundles, or individual components ready for deployment.</p>
              </div>
            </div>
          </div>

          <div className={styles.ctaSection}>
            <button 
              className={styles.primaryButton}
              onClick={() => window.location.href = '/app'}
            >
              <Upload size={20} />
              Try It Now - It's Free!
            </button>
          </div>
        </div>
      </section>

      {/* Trust Section */}
      <section className={styles.trust}>
        <div className={styles.container}>
          <h2 className={styles.sectionTitle}>Built for Security & Privacy</h2>
          <div className={styles.trustGrid}>
            <div className={styles.trustItem}>
              <div className={styles.trustIcon}>🔒</div>
              <h3>No Permanent Storage</h3>
              <p>Certificates are processed in memory only and deleted after your session ends.</p>
            </div>
            <div className={styles.trustItem}>
              <div className={styles.trustIcon}>🌐</div>
              <h3>HTTPS Only</h3>
              <p>All data transmission is encrypted end-to-end with modern TLS encryption.</p>
            </div>
            <div className={styles.trustItem}>
              <div className={styles.trustIcon}>⏱️</div>
              <h3>Session Based</h3>
              <p>Your data is isolated to your session and automatically expires for maximum privacy.</p>
            </div>
            <div className={styles.trustItem}>
              <div className={styles.trustIcon}>🏠</div>
              <h3>Open Source</h3>
              <p>Fully open source and Docker-ready. Deploy on your own infrastructure if needed.</p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className={styles.footer}>
        <div className={styles.container}>
          <div className={styles.footerContent}>
            <div className={styles.footerSection}>
              <h3>Product</h3>
              <a href="/app">Certificate Analyzer</a>
              <a href="#features">Features</a>
              <a href="/docs">Documentation</a>
              <a href="/help">Help Center</a>
            </div>
            <div className={styles.footerSection}>
              <h3>Support</h3>
              <a href="/faq">FAQ</a>
              <a href="mailto:support@cert-analyzer.tools">Contact</a>
              <a href="/status">System Status</a>
              <a href="/changelog">Changelog</a>
            </div>
            <div className={styles.footerSection}>
              <h3>Legal</h3>
              <a href="/privacy">Privacy Policy</a>
              <a href="/terms">Terms of Service</a>
              <a href="/security">Security</a>
            </div>
            <div className={styles.footerSection}>
              <h3>Community</h3>
              <a href="https://github.com/your-repo">GitHub</a>
              <a href="/blog">Blog</a>
              <a href="https://twitter.com/cert-analyzer">Twitter</a>
            </div>
          </div>
          <div className={styles.footerBottom}>
            <p>&copy; 2025 Certificate Analyzer. Made with ❤️ for the developer community.</p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default LandingPage;