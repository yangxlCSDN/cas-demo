package com.jielin.casclientspringboot.filter;

import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.util.ReflectUtils;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;

import javax.net.ssl.HostnameVerifier;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * @ClassName: AbstractTicketValidationFilter.java
 * @author: yangxl
 * @version: 1.0.0
 * @createTime: 2019年08月20日 14:23:00
 * @description: 拷贝cas-client中的源码，放开部分权限
 */
public abstract class AbstractTicketValidationFilter extends AbstractCasFilter {
    public TicketValidator ticketValidator;
    public boolean redirectAfterValidation = true;
    public boolean exceptionOnValidationFailure = false;
    public boolean useSession = true;

    public AbstractTicketValidationFilter(Protocol protocol) {
        super(protocol);
    }

    protected TicketValidator getTicketValidator(FilterConfig filterConfig) {
        return this.ticketValidator;
    }

    protected Properties getSSLConfig() {
        Properties properties = new Properties();
        String fileName = this.getString(ConfigurationKeys.SSL_CONFIG_FILE);
        if (fileName != null) {
            FileInputStream fis = null;

            try {
                fis = new FileInputStream(fileName);
                properties.load(fis);
                this.logger.trace("Loaded {} entries from {}", properties.size(), fileName);
            } catch (IOException var8) {
                this.logger.error(var8.getMessage(), var8);
            } finally {
                CommonUtils.closeQuietly(fis);
            }
        }

        return properties;
    }

    protected HostnameVerifier getHostnameVerifier() {
        Class<? extends HostnameVerifier> className = this.getClass(ConfigurationKeys.HOSTNAME_VERIFIER);
        String config = this.getString(ConfigurationKeys.HOSTNAME_VERIFIER_CONFIG);
        if (className != null) {
            return config != null ? (HostnameVerifier)ReflectUtils.newInstance(className, new Object[]{config}) : (HostnameVerifier)ReflectUtils.newInstance(className, new Object[0]);
        } else {
            return null;
        }
    }

    protected void initInternal(FilterConfig filterConfig) throws ServletException {
        this.setExceptionOnValidationFailure(this.getBoolean(ConfigurationKeys.EXCEPTION_ON_VALIDATION_FAILURE));
        this.setRedirectAfterValidation(this.getBoolean(ConfigurationKeys.REDIRECT_AFTER_VALIDATION));
        this.setUseSession(this.getBoolean(ConfigurationKeys.USE_SESSION));
        if (!this.useSession && this.redirectAfterValidation) {
            this.logger.warn("redirectAfterValidation parameter may not be true when useSession parameter is false. Resetting it to false in order to prevent infinite redirects.");
            this.setRedirectAfterValidation(false);
        }

        this.setTicketValidator(this.getTicketValidator(filterConfig));
        super.initInternal(filterConfig);
    }

    public void init() {
        super.init();
        CommonUtils.assertNotNull(this.ticketValidator, "ticketValidator cannot be null.");
    }

    protected boolean preFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        return true;
    }

    protected void onSuccessfulValidation(HttpServletRequest request, HttpServletResponse response, Assertion assertion) {
    }

    protected void onFailedValidation(HttpServletRequest request, HttpServletResponse response) {
    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        if (this.preFilter(servletRequest, servletResponse, filterChain)) {
            HttpServletRequest request = (HttpServletRequest) servletRequest;
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            String ticket = this.retrieveTicketFromRequest(request);
            if (CommonUtils.isNotBlank(ticket)) {
                this.logger.debug("Attempting to validate ticket: {}", ticket);

                try {
                    Assertion assertion = this.ticketValidator.validate(ticket, this.constructServiceUrl(request, response));
                    this.logger.debug("Successfully authenticated user: {}", assertion.getPrincipal().getName());
                    request.setAttribute("_const_cas_assertion_", assertion);
                    if (this.useSession) {
                        request.getSession().setAttribute("_const_cas_assertion_", assertion);
                    }

                    this.onSuccessfulValidation(request, response, assertion);
                    if (this.redirectAfterValidation) {
                        this.logger.debug("Redirecting after successful ticket validation.");
                        response.sendRedirect(this.constructServiceUrl(request, response));
                        return;
                    }
                } catch (TicketValidationException var8) {
                    this.logger.debug(var8.getMessage(), var8);
                    this.onFailedValidation(request, response);
                    if (this.exceptionOnValidationFailure) {
                        throw new ServletException(var8);
                    }

                    response.sendError(403, var8.getMessage());
                    return;
                }
            }

            filterChain.doFilter(request, response);
        }
    }

    public final void setTicketValidator(TicketValidator ticketValidator) {
        this.ticketValidator = ticketValidator;
    }

    public final void setRedirectAfterValidation(boolean redirectAfterValidation) {
        this.redirectAfterValidation = redirectAfterValidation;
    }

    public final void setExceptionOnValidationFailure(boolean exceptionOnValidationFailure) {
        this.exceptionOnValidationFailure = exceptionOnValidationFailure;
    }

    public final void setUseSession(boolean useSession) {
        this.useSession = useSession;
    }

    public TicketValidator getTicketValidator() { return ticketValidator; }

    public boolean isRedirectAfterValidation() { return redirectAfterValidation; }

    public boolean isExceptionOnValidationFailure() { return exceptionOnValidationFailure; }

    public boolean isUseSession() { return useSession; }

}
