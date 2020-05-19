package com.ZAP_Selenium;
import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import org.junit.*;
import org.openqa.selenium.Proxy;
import org.openqa.selenium.WebDriver;
import org.zaproxy.clientapi.core.Alert;
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
private static final String ZAP_APIKEY = ""; //TEST S
// Provide Chrome driver path
private static final String BROWSER_DRIVER_PATH = "C:\\Users\\User\\eclipse-workspace\\AttraProject\\chromedriver_win32\\chromedriver.exe";
private final static String MEDIUM = "MEDIUM";
    private final static String HIGH = "HIGH";
 
    private WebDriver driver;
    private ClientApi zapClientAPI; //TEST D
private WebSiteNavigation siteNavigation;
    int currentScanID;
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
    public void setUp()
    {
   
    zapClientAPI = new ClientApi(ZAP_PROXYHOST, 8098); //TEST DS
   
    log.info("Started a new session: Scanner");
    // Create ZAP API client
    
    log.info("Created client to ZAP API");
    // Create driver object
    driver = BrowserDriverFactory.createChromeDriver(createZapProxyConfiguration(), BROWSER_DRIVER_PATH);
    siteNavigation = new WebSiteNavigation(driver);
    // First test the "Register a new user"
 //   siteNavigation.registerNewUser();
    }
    /*
     * Method to close the driver connection
     */
    @After
    public void tearDown()
    {
    driver.quit();
    }
// ZAP Operations -- filterAlerts, setAlert_AttackStrength, activateZapPolicy, spiderwithZAP, scanWithZAP
// ---------------------------------------------------------------------------------------------------------
   /*
    * Method to filter the generated alerts based on Risk and Confidence
    */
    private List<Alert> filterAlerts(List<Alert> alerts)
    {
    List<Alert> filteredAlerts = new ArrayList<Alert>();
        for (Alert alert : alerts)
        {
        // Filtering based on Risk: High and Confidence: Not Low
            if (alert.getRisk().equals(Alert.Risk.High) && alert.getConfidence() != Alert.Confidence.Low)
            filteredAlerts.add(alert);
        }
        return filteredAlerts;
    }
  /*
     * Method to configure spider settings, execute ZAP spider, log the progress and found URLs
     */
    public void spiderWithZap() throws ClientApiException
    {
    log.info("Spidering started");
  
    ApiResponse resp = zapClientAPI.spider.scan(ZAP_APIKEY, WebSiteNavigation.BASE_URL, "", "", "", "");
   String scanid = ((ApiResponseElement)resp).getValue();
 
   int progressPercent  = 0;
        while (progressPercent < 100) {
        	progressPercent=	 Integer.parseInt(((ApiResponseElement)zapClientAPI.spider.status(scanid)).getValue());
     
        log.info("Spider is " + progressPercent + "% complete.");
        try
        {
                Thread.sleep(1000);
            }
        catch (InterruptedException e)
        {
                e.printStackTrace();
            }
        }
      
        log.info("Spidering ended");
    }
    /*
     * Method to execute scan and log the progress
     */
    public void scanWithZap() throws ClientApiException
    {
    log.info("Scanning started");
    // Execute the ZAP scanner
   zapClientAPI.ascan.scan(ZAP_APIKEY,  WebSiteNavigation.BASE_URL, "True", "False", "", "", "");
    int progressPercent  = 0;
        while (progressPercent < 100) {
        progressPercent =  Integer.parseInt(((ApiResponseElement)zapClientAPI.ascan.status("")).getValue());

        log.info("Scan is " + progressPercent + "% complete.");
        try
        {
                Thread.sleep(1000);
            }
        catch (InterruptedException e)
        {
                e.printStackTrace();
            }
        
        }
        log.info("Scanning ended");
    }

    @Test
    public void testVulnerabilitiesAfterLogin() throws Exception
    {
    siteNavigation.loginAsUser();
   // siteNavigation.navigateAfterLogin();
    // Using ZAP Spider
    log.info("Started spidering");
    log.info("After Login");
   spiderWithZap();   
    log.info("Ended spidering");
  
    // Using ZAP Scanner
    log.info("Started scanning");
    scanWithZap();           //TEST SANAT
    log.info("Ended scanning");
 
  
    FileOutputStream fout =new FileOutputStream(new File("F:\\tmp\\myreport_ZAP1.xml"));
	fout.write(zapClientAPI.core.xmlreport(ZAP_APIKEY));
	fout.close();
    System.out.println(new String(zapClientAPI.core.xmlreport(ZAP_APIKEY))); //To Print the report
   
    }
}