package com.jielin.casclientspringboot.filter;
import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.util.CommonUtils;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @ClassName: AbstractCasFilter.java
 * @author: yangxl
 * @version: 1.0.0
 * @createTime: 2019年08月20日 14:19:00
 * @description: 拷贝cas-client中的源码，放开部分权限
 */
public abstract class AbstractCasFilter extends AbstractConfigurationFilter {
    public static final String CONST_CAS_ASSERTION = "_const_cas_assertion_";
    private Protocol protocol;
    private boolean encodeServiceUrl = true;
    private String serverName;
    private String service;

    protected AbstractCasFilter(Protocol protocol) {
        this.protocol = protocol;
    }

    public final void init(FilterConfig filterConfig) throws ServletException {
        super.init(filterConfig);
        if (!this.isIgnoreInitConfiguration()) {
            this.setServerName(this.getString(ConfigurationKeys.SERVER_NAME));
            this.setService(this.getString(ConfigurationKeys.SERVICE));
            this.setEncodeServiceUrl(this.getBoolean(ConfigurationKeys.ENCODE_SERVICE_URL));
            this.initInternal(filterConfig);
        }

        this.init();
    }

    protected void initInternal(FilterConfig filterConfig) throws ServletException {
    }

    public void init() {
        CommonUtils.assertTrue(CommonUtils.isNotEmpty(this.serverName) || CommonUtils.isNotEmpty(this.service), "serverName or service must be set.");
        CommonUtils.assertTrue(CommonUtils.isBlank(this.serverName) || CommonUtils.isBlank(this.service), "serverName and service cannot both be set.  You MUST ONLY set one.");
    }

    public void destroy() {
    }

    protected final String constructServiceUrl(HttpServletRequest request, HttpServletResponse response) {
        return CommonUtils.constructServiceUrl(request, response, this.service, this.serverName, this.protocol.getServiceParameterName(), this.protocol.getArtifactParameterName(), this.encodeServiceUrl);
    }

    public final void setServerName(String serverName) {
        if (serverName != null && serverName.endsWith("/")) {
            this.serverName = serverName.substring(0, serverName.length() - 1);
            this.logger.info("Eliminated extra slash from serverName [{}].  It is now [{}]", serverName, this.serverName);
        } else {
            this.serverName = serverName;
        }

    }

    public final void setService(String service) {
        this.service = service;
    }

    public final void setEncodeServiceUrl(boolean encodeServiceUrl) {
        this.encodeServiceUrl = encodeServiceUrl;
    }

    protected Protocol getProtocol() {
        return this.protocol;
    }

    protected String retrieveTicketFromRequest(HttpServletRequest request) {
        return CommonUtils.safeGetParameter(request, this.protocol.getArtifactParameterName());
    }
}
