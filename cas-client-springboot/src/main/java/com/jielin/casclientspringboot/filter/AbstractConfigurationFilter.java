package com.jielin.casclientspringboot.filter;

import org.jasig.cas.client.configuration.ConfigurationKey;
import org.jasig.cas.client.configuration.ConfigurationStrategy;
import org.jasig.cas.client.configuration.ConfigurationStrategyName;
import org.jasig.cas.client.util.ReflectUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;

/**
 * @ClassName: AbstractConfigurationFilter.java
 * @author: yangxl
 * @version: 1.0.0
 * @createTime: 2019年08月20日 14:18:00
 * @description: 拷贝cas-client中的源码，放开部分权限
 */
public abstract class AbstractConfigurationFilter implements Filter {
    private static final String CONFIGURATION_STRATEGY_KEY = "configurationStrategy";
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());
    private boolean ignoreInitConfiguration = false;
    private ConfigurationStrategy configurationStrategy;

    public AbstractConfigurationFilter() {
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        String configurationStrategyName = filterConfig.getServletContext().getInitParameter("configurationStrategy");
        this.configurationStrategy = (ConfigurationStrategy) ReflectUtils.newInstance(ConfigurationStrategyName.resolveToConfigurationStrategy(configurationStrategyName), new Object[0]);
        this.configurationStrategy.init(filterConfig, this.getClass());
    }

    protected final boolean getBoolean(ConfigurationKey<Boolean> configurationKey) {
        return this.configurationStrategy.getBoolean(configurationKey);
    }

    protected final String getString(ConfigurationKey<String> configurationKey) {
        return this.configurationStrategy.getString(configurationKey);
    }

    protected final long getLong(ConfigurationKey<Long> configurationKey) {
        return this.configurationStrategy.getLong(configurationKey);
    }

    protected final int getInt(ConfigurationKey<Integer> configurationKey) {
        return this.configurationStrategy.getInt(configurationKey);
    }

    protected final <T> Class<? extends T> getClass(ConfigurationKey<Class<? extends T>> configurationKey) {
        return this.configurationStrategy.getClass(configurationKey);
    }

    public final void setIgnoreInitConfiguration(boolean ignoreInitConfiguration) {
        this.ignoreInitConfiguration = ignoreInitConfiguration;
    }

    protected final boolean isIgnoreInitConfiguration() {
        return this.ignoreInitConfiguration;
    }
}

