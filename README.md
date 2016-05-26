# regexp-fundamental-requirements

Several fundamental requirements for regexp’s were derived after observing several WAF bypass write-ups and studying tricky conditions of metacharacters. They were classified and put in the table. In the following table, middle column contain description of discovered requirement in detail; whereas right column gives a regular expression-based example, which is designed to find discovered requirement in set of rules, tuned to have minimum false positive rate.


|#| Requirement  | Vulnerable regex example  | Bypass example |
|---|---|---|---|
|1|  Regexp should avoid using ^ (alternative: \A) and $ (alternative: \Z) symbols, which are metacharacters for start and end of a string. It is possible to bypass regex by inserting any symbol in front or after regexp. | `(^a|a$)`  |   `%20a%20`
|2| Regexp should be case-insensitive. It is possible to bypass regex using upper or lower cases in words. [Modsecurity transformation commands](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#cmdLine) (which are applied on string before regex pattern is applied) can also be included in tests to cover more regexps.  |  `http` | `hTtP`
|3| In case modifier /m is not (globally) specified, regexp should avoid using dot “.” symbol, which means every symbol except newline (\n). It is possible to bypass regex using [newline injection](https://www.htbridge.com/blog/bypassing-bitrix-web-application-firewall-via-tiny-regexp-error.html).  |  `a.*b` | `a%0Ab`
|4|  Regexp should not be vulnerable to ReDoS. [OWASP ReDoS article](https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS) 1. Find various evil patterns.  2. Generate evil string using e.g. “SDL Regex Fuzzer”  |  `(a+)+`  |  `aaaaaaaaaaaaaaaaaaaa!`
|5| Number of repetitions of set or group {} should be carefully used, as one can bypass such limitation by lowering or increasing specified numbers.  |  `a{1,5}` | `aaaaaa (6 times)`
|6| Best Practice from [slides of Ivan Novikov](http://www.slideshare.net/d0znpp/lie-tomephd2013): Modsecurity should avoid using t:base64Decode function (t:base64DecodeExt instead).  |  `t:base64Decode` | `detected=bypassed` 
|7|  Regexp should only use plus “+” metacharacter in places where it is necessary, as it means “one or more”. Alternative metacharacter star “*”, which means “zero or more” is generally preferred. |  `a'\s+\d` | `a'5`
|8| Usage of wildcards should be reasonable. \r\n characters can often be bypassed by either substitution, or by using newline alternative \v, \f and others. Wildcard \b has different meanings while using wildcard in square brackets (has meaning “backspace”) and in plain regex (has meaning “word boundary”), as classified in [RegexLib article](http://regexlib.com/CheatSheet.aspx).  | `a[^\n]*$`  | `a\r`
|9| Regexp should be applied to right scope of inputs: Cookies names and values, Argument names and values, Header names and values, Files argument names and content. Modsecurity: `grep -oP 'SecRule(.*?)"' -n` Other WAFs: manual observation. |  Argument values  | Cookie names and values
|10| Regular expression writers should be careful while using only whitespace character (%20) as separators. Rule can be bypassed e.g. with newline character, or alternatives.  |  `a\s(and|not |or)\sb` | `a not b`

##### Experimental rules (probably to be removed):
|#| Requirement  | Vulnerable regex example  | Bypass example |
|---|---|---|---|
|11| Greediness of regular expressions should be considered. Highlight of this topic is well done in [Chapter 9 of Jan Goyvaert’s tutorial](https://www.princeton.edu/~mlovett/reference/Regular-Expressions.pdf). While greediness itself does not create bypasses, bad implementation of regexp Greediness can raise False Positive rate. This can cause excessive log-file flooding, forcing vulnerable rule or even whole WAF to be switched off.  |   |
