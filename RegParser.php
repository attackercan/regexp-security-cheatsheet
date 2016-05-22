<html>
<head>
<style>
<!--
<pre> tags wrapping 
http://www.longren.io/wrapping-text-inside-pre-tags/
-->

pre {
 white-space: pre-wrap;       /* css-3 */
 white-space: -moz-pre-wrap !important;  /* Mozilla, since 1999 */
 white-space: -pre-wrap;      /* Opera 4-6 */
 white-space: -o-pre-wrap;    /* Opera 7 */
 word-wrap: break-word;       /* Internet Explorer 5.5+ */
 width: 99%;
}
</style>
</head>
<body>

<?php

	// var_dump parameters for debug
ini_set('xdebug.var_display_max_depth', 5);
ini_set('xdebug.var_display_max_children', 256);
ini_set('xdebug.var_display_max_data', 1024);


$file = file('crs.txt');

$rules = array(
	'Rule 1 (Regexp should avoid using metacharacters for start and end of a string. It is possible to bypass regex by inserting any symbol in front or after regexp)'
		=> '/(?:^|[^\[\\\])(\^|\\\A|\$|\\\Z)/',
		
	'Rule 2'
		=> '//',
		
	'Rule 3 (Regexp should avoid using dot “.” symbol, which means every symbol except newline (\n). It is possible to bypass regex using newline injection).'
		=> '/[^\\\](\.\+)/',
		
	'Rule 4 (Regexp is possibly vulnerable to ReDoS).'
		=> '/(\((?:[\(\[]?)[^(]*?(?:[\)\]]?)[^\x5c][+*](?:[^\)\]]*)\)[+*])/',
		
	'Rule 5 (Number of repetitions of set or group {} should be carefully used, as one can bypass such limitation by lowering or increasing specified numbers).'
		=>  '/(\{[\d,].*?\})/',
		
	'Rule 6'
		=> '//',
		
	'Rule 7 (Regexp should likely use plus “+” metacharacter in places where it is necessary, as it means “one or more”. Alternative metacharacter star “*”, which means “zero or more” is generally preferred.)'
		=> '/(\\\[a-z][+])/i',
		
	'Rule 8 (Usage of wildcards should be reasonable. \r\n characters can often be bypassed by either substitution, or by using newline alternative \v, \f and others).'
		=> '/(\\\a|\[[^\]]*?\\\b[^\[]*?\]|\\\t|\\\r|\\\v|\\\f|\\\n)/',
		
	'Rule 9'
		=> '//',
		
	'Rule 10 (Regular expression writers should be careful while using only whitespace character (%20) for separating tag attributes. Rule can be bypassed with alternatives, i.e. newline character %0d,%0a).'
		=> '/(\[[^\]]*?\s[^\]]*?\])/',
		
	'Rule 11 (While greediness itself does not create bypasses, bad implementation of regexp Greediness can raise False Positive rate).'
		=> '/[^\\\](\.[\+|\*])[^\?]/',
	
	'//'	// empty string for debug
);

init();

function init() {
	foreach($GLOBALS['file'] as $string_id => $string) {
		$string = trim($string);
		$string = str_replace('<', '&lt;', $string);	// fix for good HTML output
		
		$results_for_string = applyAllRules($string);
		// var_dump($results_for_string);
		// die();

		foreach($results_for_string as $rule_name => $matchArrayData) {
			
			if($highlighedString = drawMistakes($string, $matchArrayData)) {
				
				echo "Line ".$string_id." => <pre>".$highlighedString."</pre>".$rule_name."<hr>\r\n\r\n";
				
			}
		}
	}
}

function applyAllRules($string) {
	$results = array();
	
	foreach($GLOBALS['rules'] as $name => $rule) {
		$result = applyRule($rule, $string);
		// if(!empty($result[0]))
			$results[$name] = $result;
	}
	
	return $results;
}

function applyRule($rule, $string) {
	
	preg_match_all($rule, $string, $match, PREG_OFFSET_CAPTURE);
	
	if(!empty($match))
		return $match;
	else
		return false;
}

function drawMistakes($string, $matches) {
	$res = $string;
	
	if(!@$matches[1])
		return false;
	
	foreach(array_reverse($matches[1]) as $match) {	// do substr in reverse order so offsets will not brake
		$res = drawOneMistake($res, $match);
	}
	
	return $res;
}

function drawOneMistake($string, $one_match) {
	
	$offset = $one_match[1];
	$length = strlen($one_match[0]);
	
	if(($real_offset = $offset-$length+1) < $offset) $real_offset = $offset;		// omg, maths!
	
	$before	= substr($string, 0, $real_offset);
	$match	= substr($string, $offset, $length);
	$after	= substr($string, $offset+$length);
	
	$res = $before."<font color='red'>".$match."</font>".$after;
	
	return $res;
}

?>

</body>
</html>