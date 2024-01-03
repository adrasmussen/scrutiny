package web

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"github.com/analogj/go-util/utils"
	"github.com/analogj/scrutiny/webapp/backend/pkg/config"
	"github.com/analogj/scrutiny/webapp/backend/pkg/errors"
	"github.com/analogj/scrutiny/webapp/backend/pkg/web/handler"
	"github.com/analogj/scrutiny/webapp/backend/pkg/web/middleware"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"net/http"
	"path/filepath"
	"strings"
)

type AppEngine struct {
	Config config.Interface
	Logger *logrus.Entry
}

func (ae *AppEngine) Setup(logger *logrus.Entry) *gin.Engine {
	r := gin.New()

	r.Use(middleware.LoggerMiddleware(logger))
	r.Use(middleware.RepositoryMiddleware(ae.Config, logger))
	r.Use(middleware.ConfigMiddleware(ae.Config))
	r.Use(gin.Recovery())

	basePath := ae.Config.GetString("web.listen.basepath")
	logger.Debugf("basepath: %s", basePath)

	base := r.Group(basePath)
	{
		api := base.Group("/api")
		{
			api.GET("/health", handler.HealthCheck)
			api.POST("/health/notify", handler.SendTestNotification) //check if notifications are configured correctly

			api.POST("/devices/register", handler.RegisterDevices)         //used by Collector to register new devices and retrieve filtered list
			api.GET("/summary", handler.GetDevicesSummary)                 //used by Dashboard
			api.GET("/summary/temp", handler.GetDevicesSummaryTempHistory) //used by Dashboard (Temperature history dropdown)
			api.POST("/device/:wwn/smart", handler.UploadDeviceMetrics)    //used by Collector to upload data
			api.POST("/device/:wwn/selftest", handler.UploadDeviceSelfTests)
			api.GET("/device/:wwn/details", handler.GetDeviceDetails) //used by Details
			api.DELETE("/device/:wwn", handler.DeleteDevice)          //used by UI to delete device

			api.GET("/settings", handler.GetSettings)   //used to get settings
			api.POST("/settings", handler.SaveSettings) //used to save settings
		}
	}

	//Static request routing
	base.StaticFS("/web", http.Dir(ae.Config.GetString("web.src.frontend.path")))

	//redirect base url to /web
	base.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, basePath+"/web")
	})

	//catch-all, serve index page.
	r.NoRoute(func(c *gin.Context) {
		c.File(fmt.Sprintf("%s/index.html", ae.Config.GetString("web.src.frontend.path")))
	})
	return r
}

func (ae *AppEngine) Start() error {
	//set the gin mode
	gin.SetMode(gin.ReleaseMode)
	if strings.ToLower(ae.Config.GetString("log.level")) == "debug" {
		gin.SetMode(gin.DebugMode)
	}

	//check if the database parent directory exists, fail here rather than in a handler.
	if !utils.FileExists(filepath.Dir(ae.Config.GetString("web.database.location"))) {
		return errors.ConfigValidationError(fmt.Sprintf(
			"Database parent directory does not exist. Please check path (%s)",
			filepath.Dir(ae.Config.GetString("web.database.location"))))
	}

	r := ae.Setup(ae.Logger)
	addr := fmt.Sprintf("%s:%s", ae.Config.GetString("web.listen.host"), ae.Config.GetString("web.listen.port"))

	if ! ae.Config.GetBool("web.tls.usetls") {
		return r.Run(addr)
	} else {
		//if tls is active, the minimal requirements are the server cert and key
		cert, err := tls.LoadX509KeyPair(ae.Config.GetString("web.tls.certfile"),ae.Config.GetString("web.tls.keyfile"))

		if err != nil {
			return errors.ConfigValidationError(fmt.Sprintf(
				"Failed to load server certificate keypair."))
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		//if we want to verify clients, we also need the appropriate ca certs
		//
		//AppendCertsFromPEM calls AddCerts, which won't add duplicates to the pool
		if ae.Config.GetBool("web.tls.verifyclient") {	
			certPool, err := x509.SystemCertPool()

			if err != nil {
				return errors.ConfigValidationError(fmt.Sprintf(
					"Failed to load system CA certificates."))				
			}

			caCertFile := ae.Config.GetString("web.tls.cacertfile")

			if caCertFile != "" {
				caCertPEM, err := ioutil.ReadFile(caCertFile)

				if err != nil {
					return errors.ConfigValidationError(fmt.Sprintf(
						"Failed to load CA certificate."))		
				}

				loaded := certPool.AppendCertsFromPEM(caCertPEM)

				if ! loaded {
					return errors.ConfigValidationError(fmt.Sprintf(
						"Invalid certificate in CA PEM."))
				}
			}

			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			tlsConfig.ClientCAs = certPool 
		}

		// since there is no clean way to feed tlsConfig into the gin wrapper, we have to
		// manually handle everything
		server := http.Server{
			Addr: addr,
			Handler: r,
			TLSConfig: tlsConfig,
		}

		err = server.ListenAndServeTLS("", "")
		return err
	}
}
