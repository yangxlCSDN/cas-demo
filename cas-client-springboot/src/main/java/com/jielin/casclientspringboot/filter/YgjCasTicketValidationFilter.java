package com.jielin.casclientspringboot.filter;

import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.proxy.*;
import org.jasig.cas.client.ssl.HttpURLConnectionFactory;
import org.jasig.cas.client.ssl.HttpsURLConnectionFactory;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.util.ReflectUtils;
import org.jasig.cas.client.validation.*;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * @ClassName: YgjCasTicketValidationFilter.java
 * @author: yangxl
 * @version: 1.0.0
 * @createTime: 2019年08月20日 14:26:00
 * @description: 自定义ticket校验filetr
 */
public class YgjCasTicketValidationFilter extends AbstractTicketValidationFilter {
    private static final String[] RESERVED_INIT_PARAMS;
    private String proxyReceptorUrl;
    private Timer timer;
    private TimerTask timerTask;
    private int millisBetweenCleanUps;
    protected Class<? extends Cas20ServiceTicketValidator> defaultServiceTicketValidatorClass;
    protected Class<? extends Cas20ProxyTicketValidator> defaultProxyTicketValidatorClass;
    private ProxyGrantingTicketStorage proxyGrantingTicketStorage;

    public YgjCasTicketValidationFilter() {
        this(Protocol.CAS2);
        this.defaultServiceTicketValidatorClass = Cas20ServiceTicketValidator.class;
        this.defaultProxyTicketValidatorClass = Cas20ProxyTicketValidator.class;
    }

    protected YgjCasTicketValidationFilter(Protocol protocol) {
        super(protocol);
        this.proxyGrantingTicketStorage = new ProxyGrantingTicketStorageImpl();
    }

    protected void initInternal(FilterConfig filterConfig) throws ServletException {
        this.setProxyReceptorUrl(this.getString(ConfigurationKeys.PROXY_RECEPTOR_URL));
        Class<? extends ProxyGrantingTicketStorage> proxyGrantingTicketStorageClass = this.getClass(ConfigurationKeys.PROXY_GRANTING_TICKET_STORAGE_CLASS);
        if (proxyGrantingTicketStorageClass != null) {
            this.proxyGrantingTicketStorage = (ProxyGrantingTicketStorage) ReflectUtils.newInstance(proxyGrantingTicketStorageClass, new Object[0]);
            if (this.proxyGrantingTicketStorage instanceof AbstractEncryptedProxyGrantingTicketStorageImpl) {
                AbstractEncryptedProxyGrantingTicketStorageImpl p = (AbstractEncryptedProxyGrantingTicketStorageImpl) this.proxyGrantingTicketStorage;
                String cipherAlgorithm = this.getString(ConfigurationKeys.CIPHER_ALGORITHM);
                String secretKey = this.getString(ConfigurationKeys.SECRET_KEY);
                p.setCipherAlgorithm(cipherAlgorithm);

                try {
                    if (secretKey != null) {
                        p.setSecretKey(secretKey);
                    }
                } catch (Exception var7) {
                    throw new RuntimeException(var7);
                }
            }
        }

        this.millisBetweenCleanUps = this.getInt(ConfigurationKeys.MILLIS_BETWEEN_CLEAN_UPS);
        super.initInternal(filterConfig);
    }

    public void init() {
        super.init();
        CommonUtils.assertNotNull(this.proxyGrantingTicketStorage, "proxyGrantingTicketStorage cannot be null.");
        if (this.timer == null) {
            this.timer = new Timer(true);
        }

        if (this.timerTask == null) {
            this.timerTask = new CleanUpTimerTask(this.proxyGrantingTicketStorage);
        }

        this.timer.schedule(this.timerTask, (long) this.millisBetweenCleanUps, (long) this.millisBetweenCleanUps);
    }

    private <T> T createNewTicketValidator(Class<? extends Cas20ServiceTicketValidator> ticketValidatorClass, String casServerUrlPrefix, Class<T> clazz) {
        return ticketValidatorClass == null ? ReflectUtils.newInstance(clazz, new Object[]{casServerUrlPrefix}) : ReflectUtils.newInstance(String.valueOf(ticketValidatorClass), new Object[]{casServerUrlPrefix});
    }

    protected final TicketValidator getTicketValidator(FilterConfig filterConfig) {
        boolean allowAnyProxy = this.getBoolean(ConfigurationKeys.ACCEPT_ANY_PROXY);
        String allowedProxyChains = this.getString(ConfigurationKeys.ALLOWED_PROXY_CHAINS);
        String casServerUrlPrefix = this.getString(ConfigurationKeys.CAS_SERVER_URL_PREFIX);
        Class<? extends Cas20ServiceTicketValidator> ticketValidatorClass = this.getClass(ConfigurationKeys.TICKET_VALIDATOR_CLASS);
        Object validator;
        if (!allowAnyProxy && !CommonUtils.isNotBlank(allowedProxyChains)) {
            validator = (Cas20ServiceTicketValidator)this.createNewTicketValidator(ticketValidatorClass, casServerUrlPrefix, this.defaultServiceTicketValidatorClass);
        } else {
            Cas20ProxyTicketValidator v = (Cas20ProxyTicketValidator)this.createNewTicketValidator(ticketValidatorClass, casServerUrlPrefix, this.defaultProxyTicketValidatorClass);
            v.setAcceptAnyProxy(allowAnyProxy);
            v.setAllowedProxyChains(CommonUtils.createProxyList(allowedProxyChains));
            validator = v;
        }

        ((Cas20ServiceTicketValidator) validator).setProxyCallbackUrl(this.getString(ConfigurationKeys.PROXY_CALLBACK_URL));
        ((Cas20ServiceTicketValidator) validator).setProxyGrantingTicketStorage(this.proxyGrantingTicketStorage);
        HttpURLConnectionFactory factory = new HttpsURLConnectionFactory(this.getHostnameVerifier(), this.getSSLConfig());
        ((Cas20ServiceTicketValidator) validator).setURLConnectionFactory(factory);
        ((Cas20ServiceTicketValidator) validator).setProxyRetriever(new Cas20ProxyRetriever(casServerUrlPrefix, this.getString(ConfigurationKeys.ENCODING), factory));
        ((Cas20ServiceTicketValidator) validator).setRenew(this.getBoolean(ConfigurationKeys.RENEW));
        ((Cas20ServiceTicketValidator) validator).setEncoding(this.getString(ConfigurationKeys.ENCODING));
        Map<String, String> additionalParameters = new HashMap();
        List<String> params = Arrays.asList(RESERVED_INIT_PARAMS);
        Enumeration e = filterConfig.getInitParameterNames();

        while (e.hasMoreElements()) {
            String s = (String) e.nextElement();
            if (!params.contains(s)) {
                additionalParameters.put(s, filterConfig.getInitParameter(s));
            }
        }

        ((Cas20ServiceTicketValidator) validator).setCustomParameters(additionalParameters);
        return (TicketValidator) validator;
    }

    public void destroy() {
        super.destroy();
        this.timer.cancel();
    }

    protected final boolean preFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        String requestUri = request.getRequestURI();
        if (!CommonUtils.isEmpty(this.proxyReceptorUrl) && requestUri.endsWith(this.proxyReceptorUrl)) {
            try {
                CommonUtils.readAndRespondToProxyReceptorRequest(request, response, this.proxyGrantingTicketStorage);
                return false;
            } catch (RuntimeException var8) {
                this.logger.error(var8.getMessage(), var8);
                throw var8;
            }
        } else {
            return true;
        }
    }

    public final void setProxyReceptorUrl(String proxyReceptorUrl) {
        this.proxyReceptorUrl = proxyReceptorUrl;
    }

    public void setProxyGrantingTicketStorage(ProxyGrantingTicketStorage storage) {
        this.proxyGrantingTicketStorage = storage;
    }

    public void setTimer(Timer timer) {
        this.timer = timer;
    }

    public void setTimerTask(TimerTask timerTask) {
        this.timerTask = timerTask;
    }

    public void setMillisBetweenCleanUps(int millisBetweenCleanUps) {
        this.millisBetweenCleanUps = millisBetweenCleanUps;
    }

    static {
        RESERVED_INIT_PARAMS = new String[]{ConfigurationKeys.ARTIFACT_PARAMETER_NAME.getName(), ConfigurationKeys.SERVER_NAME.getName(), ConfigurationKeys.SERVICE.getName(), ConfigurationKeys.RENEW.getName(), ConfigurationKeys.LOGOUT_PARAMETER_NAME.getName(), ConfigurationKeys.ARTIFACT_PARAMETER_OVER_POST.getName(), ConfigurationKeys.EAGERLY_CREATE_SESSIONS.getName(), ConfigurationKeys.ENCODE_SERVICE_URL.getName(), ConfigurationKeys.SSL_CONFIG_FILE.getName(), ConfigurationKeys.ROLE_ATTRIBUTE.getName(), ConfigurationKeys.IGNORE_CASE.getName(), ConfigurationKeys.CAS_SERVER_LOGIN_URL.getName(), ConfigurationKeys.GATEWAY.getName(), ConfigurationKeys.AUTHENTICATION_REDIRECT_STRATEGY_CLASS.getName(), ConfigurationKeys.GATEWAY_STORAGE_CLASS.getName(), ConfigurationKeys.CAS_SERVER_URL_PREFIX.getName(), ConfigurationKeys.ENCODING.getName(), ConfigurationKeys.TOLERANCE.getName(), ConfigurationKeys.IGNORE_PATTERN.getName(), ConfigurationKeys.IGNORE_URL_PATTERN_TYPE.getName(), ConfigurationKeys.HOSTNAME_VERIFIER.getName(), ConfigurationKeys.HOSTNAME_VERIFIER_CONFIG.getName(), ConfigurationKeys.EXCEPTION_ON_VALIDATION_FAILURE.getName(), ConfigurationKeys.REDIRECT_AFTER_VALIDATION.getName(), ConfigurationKeys.USE_SESSION.getName(), ConfigurationKeys.SECRET_KEY.getName(), ConfigurationKeys.CIPHER_ALGORITHM.getName(), ConfigurationKeys.PROXY_RECEPTOR_URL.getName(), ConfigurationKeys.PROXY_GRANTING_TICKET_STORAGE_CLASS.getName(), ConfigurationKeys.MILLIS_BETWEEN_CLEAN_UPS.getName(), ConfigurationKeys.ACCEPT_ANY_PROXY.getName(), ConfigurationKeys.ALLOWED_PROXY_CHAINS.getName(), ConfigurationKeys.TICKET_VALIDATOR_CLASS.getName(), ConfigurationKeys.PROXY_CALLBACK_URL.getName(), ConfigurationKeys.RELAY_STATE_PARAMETER_NAME.getName()};
    }

    @Override
    public final void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
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
                    createToken(ticket, assertion, response);
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


    private void createToken(String ticket, Assertion assertion, HttpServletResponse response) {
        AttributePrincipal principal = assertion.getPrincipal();
        String userID = "";
        if (principal != null) {
            Map params = principal.getAttributes();
            Object userId = params.get("userId");
            if (userId != null) {
                userID = userId.toString();
            }
        }

    }
}