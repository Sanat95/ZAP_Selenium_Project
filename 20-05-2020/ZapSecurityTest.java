package com.ZAP_Selenium;

import java.io.File;
import java.io.FileOutputStream;
import java.util.logging.Logger;

import javax.swing.JFrame;
import javax.swing.JProgressBar;

import org.junit.*;
import org.openqa.selenium.Proxy;
import org.openqa.selenium.WebDriver;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import com.ZAP_Selenium_BrowserDriver.BrowserDriverFactory;

import com.ZAP_Selenium.WebSiteNavigation;

public class ZapSecurityTest {
	/*
	 * Provide details about ZAP Proxy
	 */
	static Logger log = Logger.getLogger(ZapSecurityTest.class.getName());
	private static final String ZAP_PROXYHOST = "localhost";
	private static final int ZAP_PROXYPORT = 8098;
	// Provide Chrome driver path
	private static final String BROWSER_DRIVER_PATH = "C:\\Users\\User\\eclipse-workspace\\AttraProject\\chromedriver_win32\\chromedriver.exe";

	private WebDriver driver;
	private ClientApi zapClientAPI;
	private WebSiteNavigation siteNavigation;
	int currentScanID;
	static JProgressBar jb;
	// Create ZAP proxy by specifying proxy host and proxy port

	private static Proxy createZapProxyConfiguration() {
		Proxy proxy = new Proxy();
		proxy.setHttpProxy(ZAP_PROXYHOST + ":" + ZAP_PROXYPORT);
		proxy.setSslProxy(ZAP_PROXYHOST + ":" + ZAP_PROXYPORT);
		return proxy;
	}

	/*
	 * Method to configure ZAP scanner, API client and perform User Registration
	 */
	@Before
	public void setUp() {

		zapClientAPI = new ClientApi(ZAP_PROXYHOST, ZAP_PROXYPORT);

		log.info("Started a new session: Scanner");
		// Create ZAP API client

		log.info("Created client to ZAP API");
		// Create driver object
		driver = BrowserDriverFactory.createChromeDriver(createZapProxyConfiguration(), BROWSER_DRIVER_PATH);
		siteNavigation = new WebSiteNavigation(driver);

	}

	/*
	 * Method to close the driver connection
	 */
	@After
	public void tearDown() {
		driver.quit();
	}

	/*
	 * Method to configure spider settings, execute ZAP spider, log the progress and
	 * found URLs
	 */
	public void spiderWithZap() throws ClientApiException {
		log.info("Spidering started");
		ApiResponse resp = zapClientAPI.spider.scan(WebSiteNavigation.BASE_URL, "", "", "", "");

		String scanid = ((ApiResponseElement) resp).getValue();

		int progressPercent = 0;
		while (progressPercent < 100) {
			progressPercent = Integer.parseInt(((ApiResponseElement) zapClientAPI.spider.status(scanid)).getValue());
			jb.setString("Spider Scan Completed  " + progressPercent + "%");
			jb.setValue(progressPercent);
			log.info("Spider is " + progressPercent + "% complete.");
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}

		log.info("Spidering ended");
	}

	/*
	 * Method to execute scan and log the progress
	 */
	public void scanWithZap() throws ClientApiException {
		log.info("Scanning started");
		// Execute the ZAP scanner
		zapClientAPI.ascan.scan(WebSiteNavigation.BASE_URL, "", "", "", "", "");

		int progressPercent = 0;

		while (progressPercent < 100) {
			progressPercent = Integer.parseInt(((ApiResponseElement) zapClientAPI.ascan.status("")).getValue());
			jb.setString("Active Scan Completed  " + progressPercent + "%");

			jb.setValue(progressPercent);
			log.info("Scan is " + progressPercent + "% complete.");
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}

		}
		log.info("Scanning ended");
	}

	// *******************************
	public class CustomProgressBar extends JFrame {

		private static final long serialVersionUID = -6414386421760615531L;
		int i = 0, num = 0;

		CustomProgressBar() {

			jb = new JProgressBar(0, 100);

			jb.setBounds(40, 40, 160, 30);
			jb.setValue(0);
			jb.setStringPainted(true);
			add(jb);
			setSize(450, 550);
			setLayout(null);
		}
	}

	// **************************8
	@Test
	public void testVulnerabilitiesAfterLogin() throws Exception {

		siteNavigation.loginAsUser();

		// Using ZAP Spider
		log.info("Started spidering");
		log.info("After Login");
		//
		CustomProgressBar m = new CustomProgressBar();
		m.setVisible(true);
		//
		spiderWithZap();
		log.info("Ended spidering");

		// Using ZAP Scanner
		log.info("Started scanning");
		//scanWithZap();
		log.info("Ended scanning");
		m.setVisible(false);

		FileOutputStream fout = new FileOutputStream(new File("F:\\tmp\\myreport_ZAP1.xml"));
		fout.write(zapClientAPI.core.xmlreport());
		fout.close();
		// System.out.println(new String(zapClientAPI.core.xmlreport())); // To Print
		// the report

	}
}
