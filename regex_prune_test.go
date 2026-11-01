package libmagic

import "testing"

// Positions are frozen from C-locale glibc 2.35 regexec with nmatch=1,
// as used by FILE5_41. All 690 cases terminated normally in the reference.
func TestRegexPruneWithoutReference(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		texts   []string
		want    [][2]int
	}{
		{"((A)|(B))*(A|B)*\\1(A|B)*\\1", []string{"ABAB", "ABBA", "BAAB", "BABA", "AABAB", "ABAAB", "ABBBA", "BAAAB", "BABBA", "BBABA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {0, 4}, {0, 4}, {0, 4}, {0, 4}, {0, 4}, {0, 4}}},
		{"((A)|(B))*(A|\\1)*\\1", []string{"BABA", "ABABA", "BAABA", "BABBA", "BBABA", "ABABAABA"}, [][2]int{{0, 3}, {0, 4}, {0, 4}, {0, 4}, {0, 4}, {0, 7}}},
		{"((A)|(B))*(\\1A|B)*\\1", []string{"ABAAB", "BABAAB"}, [][2]int{{0, 4}, {0, 5}}},
		{"((A)|(B))*(\\1B?)*\\1", []string{"AABAB", "AABBA"}, [][2]int{{0, 4}, {0, 4}}},
		{"((A)|(B))+(A|B)*\\1(A|B)*\\1", []string{"ABAB", "ABBA", "BAAB", "BABA", "AABAB", "ABAAB", "ABBBA", "BAAAB", "BABBA", "BBABA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {0, 4}, {0, 4}, {0, 4}, {0, 4}, {0, 4}, {0, 4}}},
		{"((A)|(B))+(A|\\1)*\\1", []string{"BABA", "ABABA", "BAABA", "BABBA", "BBABA", "ABABAABA"}, [][2]int{{0, 3}, {0, 4}, {0, 4}, {0, 4}, {0, 4}, {0, 7}}},
		{"((A)|(B))+(\\1A|B)*\\1", []string{"ABAAB", "BABAAB"}, [][2]int{{0, 4}, {0, 5}}},
		{"((A)|(B))+(\\1B?)*\\1", []string{"AABAB", "AABBA"}, [][2]int{{0, 4}, {0, 4}}},
		{"((A)|(B)){1,2}(A|B)*\\1(A|B)*\\1", []string{"ABAB", "ABBA", "BAAB", "BABA", "ABAAB", "ABBBA", "BAAAB", "BABBA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {0, 4}, {0, 4}, {0, 4}, {0, 4}}},
		{"((A)|(B)){1,2}(A|\\1)*\\1", []string{"BABA", "BAABA", "BABAA", "BABBA"}, [][2]int{{0, 3}, {0, 4}, {0, 3}, {0, 4}}},
		{"((A)|(B)){1,2}(\\1A|B)*\\1", []string{"ABAAB", "ABBAA"}, [][2]int{{0, 3}, {0, 4}}},
		{"((AB|A)*)(B)?\\2\\2", []string{"ABAAB", "ABABA", "BABAAB", "ABABAABA"}, [][2]int{{0, 4}, {-1, -1}, {1, 5}, {0, 6}}},
		{"((AB|A)*)*(B*){1,3}B*\\2\\1", []string{"ABAAB", "BABAAB"}, [][2]int{{0, 4}, {1, 5}}},
		{"((AB|A)*)+(\\1)+(A|B)*\\4(B?)*\\3", []string{"AAABA"}, [][2]int{{0, 4}}},
		{"((AB|A)*)+A*(B*)+\\2\\2", []string{"ABAAB", "ABABA", "BABAAB", "ABABAABA"}, [][2]int{{0, 4}, {-1, -1}, {1, 5}, {0, 6}}},
		{"((AB|A)*)+\\2\\1((AB|A)*)+(B?)+\\1", []string{"AAA", "AAAB", "BAAA", "AAAAB", "AAABB", "ABAAA", "BAAAB", "BBAAA", "ABABAB"}, [][2]int{{0, 3}, {0, 4}, {1, 4}, {0, 5}, {0, 5}, {2, 5}, {1, 5}, {2, 5}, {0, 6}}},
		{"((AB|A)*)?(AB|A)*(\\3){0,2}\\3\\2", []string{"AAA", "AAAB", "BAAA", "AAABA", "AAABB", "ABAAA", "BAAAB", "BBAAA", "ABABAB"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}}},
		{"((AB|A)*)?A*(\\1){1,3}(B)*\\2", []string{"AA", "AAB", "ABA", "BAA", "AABB", "ABAA", "ABAB", "ABBA", "BAAB", "BABA", "BBAA", "AABBB", "ABAAA", "ABAAB", "ABABA", "ABABB", "ABBAA", "ABBAB", "ABBBA", "BAABB", "BABAA", "BABAB", "BABBA", "BBAAB", "BBABA", "BBBAA", "ABBABB", "BABAAB", "ABABAABA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {2, 5}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {4, 8}}},
		{"((AB|A)*){0,2}((A|B)*)?(A|B)*\\3\\4", []string{"AA", "BB", "AAB", "ABA", "ABB", "BAA", "BAB", "BBA", "AABA", "AABB", "ABAB", "ABBA", "BAAA", "BAAB", "BABA", "BBAA", "BBAB", "AAABA", "AAABB", "AABAB", "AABBA", "ABAAB", "ABABA", "ABBAB", "ABBBA", "BAAAA", "BAAAB", "BAABA", "BABAB", "BABBA", "BBAAA", "BBAAB", "BBABA", "BBBAA", "BBBAB", "ABABAB", "BABAAB", "ABABAABA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {1, 4}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {0, 3}, {0, 3}, {-1, -1}, {-1, -1}, {0, 4}, {-1, -1}, {-1, -1}, {0, 4}, {1, 5}, {1, 4}, {-1, -1}, {-1, -1}, {0, 4}, {2, 5}, {-1, -1}, {-1, -1}, {0, 3}, {0, 3}, {-1, -1}, {0, 5}, {0, 6}}},
		{"((AB|A)*){1,3}(B?){0,2}\\2\\1", []string{"ABAAB", "ABABA", "BABAAB"}, [][2]int{{0, 4}, {-1, -1}, {1, 5}}},
		{"((AB|A)*){1,3}(\\1)+(A|AB)?((A|AB)?){1,3}\\2\\1", []string{"AAA", "AAAB", "BAAA", "AAABA", "AAABB", "ABAAA", "BAAAB", "BBAAA", "ABABAB", "ABABAABA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}}},
		{"((A|AB)?)(B*)\\1(\\1)+\\1", []string{"ABABAABA"}, [][2]int{{0, 0}}},
		{"((A|AB)?)*((A|B)*){1,3}((A|B)*)B(\\5)?\\3", []string{"ABAA", "BABA", "ABAAA", "BAABA", "BABAA", "BBABA"}, [][2]int{{0, 3}, {0, 3}, {0, 3}, {0, 4}, {0, 3}, {0, 4}}},
		{"((A|AB)?)?B?(\\2)?A?\\1", []string{"ABABA"}, [][2]int{{0, 4}}},
		{"((A|AB)?){0,2}((AB|A)*)?((A|AB)?){0,2}\\6\\2", []string{"AAA", "AAAB", "BAAA", "AAABA", "AAABB", "ABAAA", "BAAAB", "BBAAA", "ABABAB"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}}},
		{"((A|AB)?){0,2}(B?)+(\\2){1,3}\\1", []string{"ABABAABA"}, [][2]int{{0, 6}}},
		{"((A|AB)?){1,3}(A){0,2}(B?)+(\\2)+\\4\\1", []string{"AA", "AAB", "ABA", "BAA", "AABA", "AABB", "ABAB", "BAAB", "BABA", "BBAA", "AABAB", "AABBA", "AABBB", "ABAAB", "ABABB", "ABBAA", "ABBAB", "ABBBA", "BAABA", "BAABB", "BABAB", "BBAAB", "BBABA", "BBBAA", "ABBABB", "BABAAB", "ABABAABA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {0, 4}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {1, 5}, {0, 5}}},
		{"((A|AB)?){1,3}(B*){0,2}((A|AB)?){0,2}\\5\\2", []string{"AAA", "AAAB", "BAAA", "AAABA", "AAABB", "ABABA", "BAAAB", "BBAAA", "ABABAB", "ABABAABA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}}},
		{"((A|B)*)((AB|A)*)?(B)?B?\\2\\4", []string{"AAA", "AAAB", "ABAA", "ABBA", "BAAA", "AAABA", "AAABB", "AABBA", "ABAAA", "ABAAB", "ABBAA", "ABBAB", "ABBBA", "BAAAB", "BABAA", "BBAAA", "ABBABB", "BABAAB"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {0, 4}, {-1, -1}, {-1, -1}, {0, 4}}},
		{"((A|B)*)(B?){1,3}(\\3)\\2", []string{"ABA", "AABA", "ABAB", "BABA", "AAABA", "AABAB", "ABABA", "BAABA", "BABAB", "BBABA", "ABABAB", "ABABAABA"}, [][2]int{{-1, -1}, {0, 2}, {-1, -1}, {-1, -1}, {0, 3}, {0, 2}, {-1, -1}, {0, 3}, {-1, -1}, {0, 2}, {-1, -1}, {0, 6}}},
		{"((A|B)*)(\\1){1,3}\\3", []string{"AAAAAA"}, [][2]int{{0, 3}}},
		{"((A|B)*)+(\\1B?)*\\1", []string{"ABA", "ABAA", "ABAAA", "ABAAB", "ABABA", "ABBAB", "BABBA", "ABABAABA"}, [][2]int{{0, 3}, {0, 4}, {0, 5}, {0, 5}, {0, 5}, {0, 5}, {0, 5}, {0, 8}}},
		{"((A|B)*)?(A|\\1)*\\1", []string{"BABBA"}, [][2]int{{0, 4}}},
		{"((A|B)*){0,2}((A|AB)?){0,2}(B?){1,3}(\\2)?\\4", []string{"ABAAB", "BABAAB"}, [][2]int{{0, 4}, {0, 5}}},
		{"((A|B)*){1,2}(A|\\1)*\\1", []string{"BABBA"}, [][2]int{{0, 4}}},
		{"((A|B)*){1,2}(\\1B?)*\\1", []string{"ABABA", "ABABAABA"}, [][2]int{{0, 5}, {0, 7}}},
		{"((A|B)*){1,3}((AB|A)*)?\\3(B?)\\1", []string{"A", "AB", "ABB", "BAB", "AAAB", "AABB", "ABAA", "ABBA", "ABBB", "BABB", "AAABB", "AABAB", "AABBA", "AABBB", "ABAAA", "ABAAB", "ABABA", "ABBAA", "ABBBA", "ABBBB", "BAAAB", "BABAB", "BABBB", "BBABB", "BABAAB", "ABABAABA"}, [][2]int{{0, 0}, {0, 0}, {0, 0}, {0, 1}, {0, 3}, {0, 3}, {0, 3}, {0, 0}, {0, 0}, {0, 1}, {0, 3}, {0, 4}, {0, 3}, {0, 3}, {0, 3}, {0, 3}, {0, 4}, {0, 0}, {0, 0}, {0, 0}, {0, 1}, {0, 4}, {0, 1}, {0, 2}, {0, 4}, {0, 4}}},
		{"(A(B)?)*(A|B)*\\1(A|B)*\\1", []string{"ABAAB", "BABAAB"}, [][2]int{{0, 4}, {1, 5}}},
		{"(A(B)?)*(A|\\1)*\\1", []string{"ABABAABA"}, [][2]int{{0, 7}}},
		{"(A(B)?)+(A|B)*\\1(A|B)*\\1", []string{"ABAAB", "BABAAB"}, [][2]int{{0, 4}, {1, 5}}},
		{"(A(B)?)+(A|\\1)*\\1", []string{"ABABAABA"}, [][2]int{{0, 7}}},
		{"(A(B)?)?(A|B)*\\1(A|B)*\\1", []string{"ABAAB", "BABAAB"}, [][2]int{{0, 4}, {1, 5}}},
		{"(A(B)?){1,2}(A|B)*\\1(A|B)*\\1", []string{"ABAAB", "BABAAB"}, [][2]int{{0, 4}, {1, 5}}},
		{"(A)*B*(A|AB)?\\2\\1", []string{"AAA", "AAAB", "BAAA", "AAABA", "AAABB", "ABABA", "BAAAB", "BBAAA", "ABABAB", "ABABAABA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}}},
		{"(A)?((A|B)*)+B?(\\3){1,3}A?\\1", []string{"AAA", "AAAB", "ABAA", "BAAA", "AAABA", "AAABB", "ABAAB", "ABABA", "BAAAB", "BABAA", "BBAAA", "ABABAB", "BABAAB", "ABABAABA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {0, 6}}},
		{"(A*B*){0,2}(A|B)*\\1(A|B)*\\1", []string{"BABAAB"}, [][2]int{{0, 5}}},
		{"(A*B*){1,2}(A|\\1)*\\1", []string{"BABA", "BAABA", "BABAA", "BABBA", "BBABA"}, [][2]int{{0, 3}, {0, 4}, {0, 3}, {0, 4}, {0, 4}}},
		{"(A?)?(A*)\\2(B?){0,2}\\1", []string{"A", "AB", "AAA", "ABB", "AAAB", "AABA", "ABBB", "AAAAA", "AAABB", "AABAA", "AABAB", "AABBA", "ABBBA", "ABBBB"}, [][2]int{{0, 0}, {0, 0}, {0, 2}, {0, 0}, {0, 2}, {0, 3}, {0, 0}, {0, 4}, {0, 2}, {0, 3}, {0, 3}, {0, 4}, {0, 0}, {0, 0}}},
		{"(A?){1,3}((AB|A)*)(\\2)+(B*){1,3}(A|AB)?\\3", []string{"AA", "AAB", "ABA", "BAA", "AABB", "ABAA", "ABAB", "ABBA", "BAAB", "BABA", "BBAA", "AABBB", "ABAAA", "ABAAB", "ABABA", "ABABB", "ABBAA", "ABBAB", "ABBBA", "BAABB", "BABAA", "BABAB", "BABBA", "BBAAB", "BBABA", "BBBAA", "ABBABB", "BABAAB"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {2, 5}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}}},
		{"(A?){1,3}A?\\1A\\1", []string{"AAA", "AAAB", "BAAA", "AAABA", "AAABB", "BAAAB", "BBAAA"}, [][2]int{{0, 2}, {0, 2}, {1, 3}, {0, 2}, {0, 2}, {1, 3}, {2, 4}}},
		{"(A?B?){0,2}(A|B)*\\1(A|B)*\\1", []string{"BABAAB"}, [][2]int{{0, 5}}},
		{"(A?B?){1,2}(A|\\1)*\\1", []string{"BABA", "BAABA", "BABAA", "BABBA"}, [][2]int{{0, 3}, {0, 4}, {0, 3}, {0, 4}}},
		{"(AB|A)*((A|AB)?){0,2}\\1\\1", []string{"ABABAABA"}, [][2]int{{-1, -1}}},
		{"(AB|A)*((A|B)*){1,3}\\2(A*)+\\1", []string{"ABA", "AABA", "BABA", "AAABA", "ABABA", "ABBAB", "BAABA", "BBABA", "ABBABB", "ABABAABA"}, [][2]int{{-1, -1}, {0, 2}, {-1, -1}, {0, 3}, {0, 4}, {0, 4}, {1, 3}, {-1, -1}, {0, 4}, {0, 7}}},
		{"(AB|A)*(B*)+\\1((AB|A)*){1,3}\\1", []string{"ABAAB", "ABABA", "BABAAB"}, [][2]int{{0, 4}, {-1, -1}, {1, 5}}},
		{"(A|AB)*(A|B)*\\1(A|B)*\\1", []string{"ABAAB", "BABAAB"}, [][2]int{{0, 4}, {1, 5}}},
		{"(A|AB)*(A|\\1)*\\1", []string{"ABABAABA"}, [][2]int{{0, 7}}},
		{"(A|AB)+(A|B)*\\1(A|B)*\\1", []string{"ABAAB", "BABAAB"}, [][2]int{{0, 4}, {1, 5}}},
		{"(A|AB)+(A|\\1)*\\1", []string{"ABABAABA"}, [][2]int{{0, 7}}},
		{"(A|AB)?(AB|A)*(\\2)+\\1", []string{"AAA", "AAAB", "BAAA", "AAABA", "AAABB", "ABAAA", "BAAAB", "BBAAA", "ABABAB"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}}},
		{"(A|AB)?(A|B)*\\1(A|B)*\\1", []string{"ABAAB", "BABAAB"}, [][2]int{{0, 4}, {1, 5}}},
		{"(A|AB)?(B*)*(\\2)?\\3\\1\\1", []string{"ABAAB", "ABABA", "BABAAB", "ABABAABA"}, [][2]int{{0, 4}, {-1, -1}, {1, 5}, {2, 6}}},
		{"(A|AB)?(B?)+(\\1){0,2}(A|AB)?\\3", []string{"ABABAABA"}, [][2]int{{-1, -1}}},
		{"(A|AB)?A*A(A|AB)?\\1\\2", []string{"AAAA", "AAAAB", "BAAAA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}}},
		{"(A|AB){1,2}(A|B)*\\1(A|B)*\\1", []string{"ABAAB", "BABAAB"}, [][2]int{{0, 4}, {1, 5}}},
		{"(A|B)*((A|B)*)?\\1(\\3){0,2}(\\3){1,3}\\1", []string{"AAAA", "BBBB", "AAAAB", "ABABB", "ABBBA", "ABBBB", "BAAAA", "BAAAB", "BABAA", "BBBBA", "ABBABB", "ABABAABA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {0, 7}}},
		{"(A|B)*(A?)+(A?)+(AB|A)*\\1\\1", []string{"BAAB", "BABA", "AABAB", "AABBA", "ABAAB", "ABABA", "BAAAB", "BAABA", "BABAA", "BABAB", "BBAAB", "BBABA", "ABABAB", "BABAAB", "ABABAABA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {0, 4}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}}},
		{"(A|B)*(A|B)*\\1(A|B)*\\1", []string{"ABAB", "ABBA", "BAAB", "BABA", "AABAB", "ABAAB", "ABBBA", "BAAAB", "BABBA", "BBABA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {0, 4}, {0, 4}, {0, 4}, {0, 4}, {0, 4}, {0, 4}}},
		{"(A|B)*(A|\\1)*\\1", []string{"BABA", "ABABA", "BAABA", "BABBA", "BBABA", "ABABAABA"}, [][2]int{{0, 3}, {0, 4}, {0, 4}, {0, 4}, {0, 4}, {0, 7}}},
		{"(A|B)*(B){0,2}(\\1)\\3(\\3){0,2}\\1", []string{"ABAAB", "ABBBA", "BABAAB", "ABABAABA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}}},
		{"(A|B)*(\\1A|B)*\\1", []string{"ABAAB", "BABAAB"}, [][2]int{{0, 4}, {0, 5}}},
		{"(A|B)*(\\1B?)*\\1", []string{"AABAB", "AABBA"}, [][2]int{{0, 4}, {0, 4}}},
		{"(A|B)+(A|B)*\\1(A|B)*\\1", []string{"ABAB", "ABBA", "BAAB", "BABA", "AABAB", "ABAAB", "ABBBA", "BAAAB", "BABBA", "BBABA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {0, 4}, {0, 4}, {0, 4}, {0, 4}, {0, 4}, {0, 4}}},
		{"(A|B)+(A|\\1)*\\1", []string{"BABA", "ABABA", "BAABA", "BABBA", "BBABA", "ABABAABA"}, [][2]int{{0, 3}, {0, 4}, {0, 4}, {0, 4}, {0, 4}, {0, 7}}},
		{"(A|B)+(\\1A|B)*\\1", []string{"ABAAB", "BABAAB"}, [][2]int{{0, 4}, {0, 5}}},
		{"(A|B)+(\\1B?)*\\1", []string{"AABAB", "AABBA"}, [][2]int{{0, 4}, {0, 4}}},
		{"(A|B){1,2}(A|B)*\\1(A|B)*\\1", []string{"ABAB", "ABBA", "BAAB", "BABA", "ABAAB", "ABBBA", "BAAAB", "BABBA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {0, 4}, {0, 4}, {0, 4}, {0, 4}}},
		{"(A|B){1,2}(A|\\1)*\\1", []string{"BABA", "BAABA", "BABAA", "BABBA"}, [][2]int{{0, 3}, {0, 4}, {0, 3}, {0, 4}}},
		{"(A|B){1,2}(\\1A|B)*\\1", []string{"ABAAB", "ABBAA"}, [][2]int{{0, 3}, {0, 4}}},
		{"(B)*((A|B)*)(AB|A)*\\1\\2", []string{"BABBA", "BABBB"}, [][2]int{{0, 4}, {0, 4}}},
		{"(B)?((A|AB)?){1,3}((A|AB)?){1,3}(\\2){0,2}\\4", []string{"AAABA"}, [][2]int{{0, 4}}},
		{"(B){0,2}(A|B)*\\2(\\1)\\1", []string{"BBBBB"}, [][2]int{{-1, -1}}},
		{"(B*)(AB|A)*((AB|A)*){0,2}((A|B)*)*\\4\\2", []string{"AAA", "AAAB", "ABAA", "BAAA", "AAABA", "AAABB", "ABAAA", "ABAAB", "ABABA", "ABBAA", "BAAAB", "BABAA", "BBAAA", "ABABAB", "BABAAB", "ABABAABA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {0, 7}}},
		{"(B*)?(B)*(A|AB)?(\\1)*A?\\1", []string{"BABBA"}, [][2]int{{0, 4}}},
		{"(B*){1,3}(\\1){0,2}(\\2)\\3((A|AB)?)\\1", []string{"A", "AA", "AB", "AAA", "AAB", "ABA", "ABB", "AAAA", "AAAB", "AABA", "AABB", "ABAA", "ABAB", "ABBA", "ABBB", "AAAAA", "AAAAB", "AAABA", "AAABB", "AABAA", "AABAB", "AABBA", "AABBB", "ABAAA", "ABAAB", "ABABA", "ABABB", "ABBAA", "ABBAB", "ABBBA", "ABBBB", "ABABAB", "AAAAAA", "ABBABB", "ABABAABA"}, [][2]int{{0, 1}, {0, 1}, {0, 2}, {0, 1}, {0, 1}, {0, 2}, {0, 2}, {0, 1}, {0, 1}, {0, 1}, {0, 1}, {0, 2}, {0, 2}, {0, 2}, {0, 2}, {0, 1}, {0, 1}, {0, 1}, {0, 1}, {0, 1}, {0, 1}, {0, 1}, {0, 1}, {0, 2}, {0, 2}, {0, 2}, {0, 2}, {0, 2}, {0, 2}, {0, 2}, {0, 2}, {0, 2}, {0, 1}, {0, 2}, {0, 2}}},
		{"(B*){1,3}A?((A|AB)?){1,3}(B)?\\3\\2", []string{"AA", "AAB", "ABA", "BAA", "AABA", "AABB", "ABAB", "BAAB", "BABA", "BBAA", "AABAB", "AABBA", "AABBB", "ABAAB", "ABABA", "ABABB", "ABBAA", "BAABA", "BAABB", "BABAB", "BBAAB", "BBABA", "BBBAA", "BABAAB", "ABABAABA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {0, 4}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {0, 5}, {1, 6}}},
		{"(B?)(B?){0,2}(\\1)*\\2", []string{"BBBBB"}, [][2]int{{0, 4}}},
		{"(B?)+(A*){0,2}(A|AB)?(B?)+(\\3){1,3}\\3", []string{"ABAAB", "ABABA", "BABAAB", "ABABAABA"}, [][2]int{{0, 4}, {-1, -1}, {0, 5}, {1, 6}}},
		{"(B?)+(A|AB)?((A|B)*){1,3}(\\2)\\4", []string{"AAA", "AAAB", "BAAA", "AAABA", "AAABB", "ABABB", "BAAAB", "BBAAA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {0, 4}, {-1, -1}, {-1, -1}}},
		{"(B?){0,2}((A|AB)?){0,2}(B)?(\\2){0,2}\\3", []string{"ABABAABA"}, [][2]int{{0, 6}}},
		{"A(A|B)*((AB|A)*)?\\1A\\3", []string{"AAAAA"}, [][2]int{{-1, -1}}},
		{"A*(B)+(B*)(A*)?\\2\\2", []string{"BBAB", "ABBAB", "BBAAB", "BBABA", "BBBAB"}, [][2]int{{0, 3}, {0, 4}, {0, 4}, {0, 3}, {0, 4}}},
		{"A*(B*)((A|B)*)A?\\2\\3", []string{"BB", "ABB", "BAA", "BAB", "BBA", "AABB", "ABAA", "ABAB", "ABBA", "BAAB", "BABA", "BBAA", "BBAB", "AAABB", "AABAA", "AABAB", "AABBA", "ABAAB", "ABABA", "ABBAA", "ABBAB", "BAABA", "BAABB", "BABAB", "BBAAB", "BBABA", "BBBAA", "BBBAB", "ABABAB", "ABABAABA"}, [][2]int{{-1, -1}, {-1, -1}, {1, 3}, {-1, -1}, {-1, -1}, {0, 2}, {2, 4}, {-1, -1}, {-1, -1}, {1, 3}, {-1, -1}, {2, 4}, {-1, -1}, {0, 3}, {0, 2}, {0, 2}, {0, 2}, {2, 4}, {-1, -1}, {3, 5}, {-1, -1}, {1, 3}, {1, 3}, {-1, -1}, {2, 4}, {-1, -1}, {0, 3}, {0, 3}, {-1, -1}, {0, 6}}},
		{"B*(A?)?(A*){1,3}\\2\\1", []string{"A", "AB", "BA", "ABA", "ABB", "BAB", "BBA", "ABAA", "ABAB", "ABBA", "ABBB", "BABA", "BABB", "BBAB", "BBBA", "ABAAA", "ABAAB", "ABABA", "ABABB", "ABBAA", "ABBAB", "ABBBA", "ABBBB", "BABAA", "BABAB", "BABBA", "BABBB", "BBABA", "BBABB", "BBBAB", "BBBBA", "ABABAB", "ABBABB", "BABAAB", "ABABAABA"}, [][2]int{{0, 0}, {0, 0}, {0, 1}, {0, 0}, {0, 0}, {0, 1}, {0, 2}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 1}, {0, 1}, {0, 2}, {0, 3}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 1}, {0, 1}, {0, 1}, {0, 1}, {0, 2}, {0, 2}, {0, 3}, {0, 4}, {0, 0}, {0, 0}, {0, 1}, {0, 0}}},
		{"B*(B?){1,3}(A*)(\\1)+A*\\3", []string{"BBAB", "BABAB", "BBAAB", "BBABA", "BBBAB", "BABAAB"}, [][2]int{{0, 3}, {0, 2}, {0, 4}, {0, 3}, {0, 4}, {0, 2}}},
		{"B?(A|B)*(A|AB)?\\2\\1", []string{"AAA", "AAAB", "BAAA", "AAABA", "AAABB", "ABAAA", "ABABB", "BAAAB", "BBAAA"}, [][2]int{{-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}, {-1, -1}}},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			m := entry{reln: '='}
			copy(m.value[:], tc.pattern)
			re := compileRule(&m)
			if re == nil {
				t.Fatal("cannot compile pattern")
			}
			for i, text := range tc.texts {
				got := [2]int{-1, -1}
				if loc := re.FindStringIndex(text); loc != nil {
					got = [2]int{loc[0], loc[1]}
				}
				if got != tc.want[i] {
					t.Errorf("text %q: index %v, want %v", text, got, tc.want[i])
				}
			}
		})
	}
}
