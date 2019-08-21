package com.jielin.casclientspringboot.filter;

import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.authentication.*;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.util.ReflectUtils;
import org.jasig.cas.client.validation.Assertion;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @ClassName: YgjAuthenticationFilter.java
 * @author: yangxl
 * @version: 1.0.0
 * @createTime: 2019年08月20日 16:48:00
 * @description: 自定义登录验证的filter
 */
public class YgjAuthenticationFilter extends AbstractCasFilter {
    private String casServerLoginUrl;
    private boolean renew;
    private boolean gateway;
    private GatewayResolver gatewayStorage;
    private AuthenticationRedirectStrategy authenticationRedirectStrategy;
    private UrlPatternMatcherStrategy ignoreUrlPatternMatcherStrategyClass;
    private static final Map<String, Class<? extends UrlPatternMatcherStrategy>> PATTERN_MATCHER_TYPES = new HashMap();

    public YgjAuthenticationFilter() {
        this(Protocol.CAS2);
    }

    protected YgjAuthenticationFilter(Protocol protocol) {
        super(protocol);
        this.renew = false;
        this.gateway = false;
        this.gatewayStorage = new DefaultGatewayResolverImpl();
        this.authenticationRedirectStrategy = new DefaultAuthenticationRedirectStrategy();
        this.ignoreUrlPatternMatcherStrategyClass = null;
    }

    protected void initInternal(FilterConfig filterConfig) throws ServletException {
        if (!this.isIgnoreInitConfiguration()) {
            super.initInternal(filterConfig);
            String loginUrl = this.getString(ConfigurationKeys.CAS_SERVER_LOGIN_URL);
            if (loginUrl != null) {
                this.setCasServerLoginUrl(loginUrl);
            } else {
                this.setCasServerUrlPrefix(this.getString(ConfigurationKeys.CAS_SERVER_URL_PREFIX));
            }

            this.setRenew(this.getBoolean(ConfigurationKeys.RENEW));
            this.setGateway(this.getBoolean(ConfigurationKeys.GATEWAY));
            String ignorePattern = this.getString(ConfigurationKeys.IGNORE_PATTERN);
            String ignoreUrlPatternType = this.getString(ConfigurationKeys.IGNORE_URL_PATTERN_TYPE);
            Class gatewayStorageClass;
            if (ignorePattern != null) {
                gatewayStorageClass = (Class)PATTERN_MATCHER_TYPES.get(ignoreUrlPatternType);
                if (gatewayStorageClass != null) {
                    this.ignoreUrlPatternMatcherStrategyClass = (UrlPatternMatcherStrategy) ReflectUtils.newInstance(gatewayStorageClass.getName(), new Object[0]);
                } else {
                    try {
                        this.logger.trace("Assuming {} is a qualified class name...", ignoreUrlPatternType);
                        this.ignoreUrlPatternMatcherStrategyClass = (UrlPatternMatcherStrategy)ReflectUtils.newInstance(ignoreUrlPatternType, new Object[0]);
                    } catch (IllegalArgumentException var7) {
                        this.logger.error("Could not instantiate class [{}]", ignoreUrlPatternType, var7);
                    }
                }

                if (this.ignoreUrlPatternMatcherStrategyClass != null) {
                    this.ignoreUrlPatternMatcherStrategyClass.setPattern(ignorePattern);
                }
            }

            gatewayStorageClass = this.getClass(ConfigurationKeys.GATEWAY_STORAGE_CLASS);
            if (gatewayStorageClass != null) {
                this.setGatewayStorage((GatewayResolver)ReflectUtils.newInstance(gatewayStorageClass, new Object[0]));
            }

            Class<? extends AuthenticationRedirectStrategy> authenticationRedirectStrategyClass = this.getClass(ConfigurationKeys.AUTHENTICATION_REDIRECT_STRATEGY_CLASS);
            if (authenticationRedirectStrategyClass != null) {
                this.authenticationRedirectStrategy = (AuthenticationRedirectStrategy)ReflectUtils.newInstance(authenticationRedirectStrategyClass, new Object[0]);
            }
        }

    }

    public void init() {
        super.init();
        String message = String.format("one of %s and %s must not be null.", ConfigurationKeys.CAS_SERVER_LOGIN_URL.getName(), ConfigurationKeys.CAS_SERVER_URL_PREFIX.getName());
        CommonUtils.assertNotNull(this.casServerLoginUrl, message);
    }

    public final void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;
        if (this.isRequestUrlExcluded(request)) {
            this.logger.debug("Request is ignored.");
            filterChain.doFilter(request, response);
        } else {
            HttpSession session = request.getSession(false);
            //获取session中存储的用户对象
            Assertion assertion = session != null ? (Assertion)session.getAttribute("_const_cas_assertion_") : null;
            // todo 当需要使用token做认证的时候需要替换此部分的代码
            if (assertion != null) {
                filterChain.doFilter(request, response);
            } else {
                String serviceUrl = this.constructServiceUrl(request, response);
                String ticket = this.retrieveTicketFromRequest(request);
                boolean wasGatewayed = this.gateway && this.gatewayStorage.hasGatewayedAlready(request, serviceUrl);
                //当session和ticket都不存在时
                if (!CommonUtils.isNotBlank(ticket) && !wasGatewayed) {
                    this.logger.debug("no ticket and no assertion found");
                    String modifiedServiceUrl;
                    if (this.gateway) {
                        this.logger.debug("setting gateway attribute in session");
                        modifiedServiceUrl = this.gatewayStorage.storeGatewayInformation(request, serviceUrl);
                    } else {
                        modifiedServiceUrl = serviceUrl;
                    }

                    this.logger.debug("Constructed service url: {}", modifiedServiceUrl);
                    String urlToRedirectTo = CommonUtils.constructRedirectUrl(this.casServerLoginUrl, this.getProtocol().getServiceParameterName(), modifiedServiceUrl, this.renew, this.gateway);
                    this.logger.debug("redirecting to \"{}\"", urlToRedirectTo);
                    this.authenticationRedirectStrategy.redirect(request, response, urlToRedirectTo);
                } else {
                    filterChain.doFilter(request, response);
                }
            }
        }
    }

    public final void setRenew(boolean renew) {
        this.renew = renew;
    }

    public final void setGateway(boolean gateway) {
        this.gateway = gateway;
    }

    public final void setCasServerUrlPrefix(String casServerUrlPrefix) {
        this.setCasServerLoginUrl(CommonUtils.addTrailingSlash(casServerUrlPrefix) + "login");
    }

    public final void setCasServerLoginUrl(String casServerLoginUrl) {
        this.casServerLoginUrl = casServerLoginUrl;
    }

    public final void setGatewayStorage(GatewayResolver gatewayStorage) {
        this.gatewayStorage = gatewayStorage;
    }

    private boolean isRequestUrlExcluded(HttpServletRequest request) {
        if (this.ignoreUrlPatternMatcherStrategyClass == null) {
            return false;
        } else {
            StringBuffer urlBuffer = request.getRequestURL();
            if (request.getQueryString() != null) {
                urlBuffer.append("?").append(request.getQueryString());
            }

            String requestUri = urlBuffer.toString();
            return this.ignoreUrlPatternMatcherStrategyClass.matches(requestUri);
        }
    }

    public final void setIgnoreUrlPatternMatcherStrategyClass(UrlPatternMatcherStrategy ignoreUrlPatternMatcherStrategyClass) {
        this.ignoreUrlPatternMatcherStrategyClass = ignoreUrlPatternMatcherStrategyClass;
    }

    static {
        PATTERN_MATCHER_TYPES.put("CONTAINS", ContainsPatternUrlPatternMatcherStrategy.class);
        PATTERN_MATCHER_TYPES.put("REGEX", RegexUrlPatternMatcherStrategy.class);
        PATTERN_MATCHER_TYPES.put("EXACT", ExactUrlPatternMatcherStrategy.class);
    }
}
