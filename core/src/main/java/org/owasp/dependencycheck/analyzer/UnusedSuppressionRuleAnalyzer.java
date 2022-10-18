/*
 * Copyright 2022 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.analyzer;

import java.util.List;
import org.owasp.dependencycheck.Engine;
import static org.owasp.dependencycheck.analyzer.AbstractSuppressionAnalyzer.SUPPRESSION_OBJECT_KEY;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.xml.suppression.SuppressionRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author jeremy
 */
public class UnusedSuppressionRuleAnalyzer extends AbstractAnalyzer {
    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(UnusedSuppressionRuleAnalyzer.class);
    private boolean reported = false;
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        logUnusedRules(engine);
    }
    /**
     * Logs unused suppression RULES.
     *
     * @param engine a reference to the ODC engine
     */
    private void logUnusedRules(Engine engine) {
        if (engine.hasObject(SUPPRESSION_OBJECT_KEY)) {
            @SuppressWarnings("unchecked")
            final List<SuppressionRule> rules = (List<SuppressionRule>) engine.getObject(SUPPRESSION_OBJECT_KEY);
            rules.forEach((rule) -> {
                if (!rule.isMatched() && !rule.isBase()) {
                    LOGGER.info("Suppression Rule had zero matches: {}", rule.toString());
                }
            });
        }
    }
    
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        //technically incorrect - but we will reuse the enabled key for this analyzer
        return Settings.KEYS.ANALYZER_VULNERABILITY_SUPPRESSION_ENABLED;
    }

    @Override
    public String getName() {
        return "Unused Suppression Rule Analyzer";
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.FINAL;
    }
    @Override
    public boolean supportsParallelProcessing() {
        return false;
    }
}
