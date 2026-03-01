/// Top common passwords from aggregated breach data (NCSC, NordPass, Have I Been Pwned).
/// Checked during password set/change to prevent use of trivially guessable passwords.
/// Case-insensitive comparison: all entries stored lowercase.
///
/// Sources: NCSC top passwords analysis, NordPass annual reports, SecLists.
use std::collections::HashSet;
use std::sync::LazyLock;

static COMMON_PASSWORDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        // Numeric sequences
        "12345678", "123456789", "1234567890", "12345678910", "123123123",
        "11111111", "00000000", "12341234", "12121212", "11223344",
        "12344321", "12348765", "87654321", "98765432", "13131313",
        "14141414", "10101010", "20202020", "69696969", "77777777",
        "88888888", "99999999", "11112222", "12131415", "12345679",
        "11111111111", "123456789a", "1234567891", "1234512345",
        // Keyboard patterns
        "qwerty123", "qwerty12", "qwertyui", "qwertyu1", "qwerty12345",
        "asdfghjk", "asdf1234", "zxcvbnm1", "1q2w3e4r", "1qaz2wsx",
        "1q2w3e4r5t", "qazwsxedc", "qweasdzxc", "zaq12wsx",
        "!qaz2wsx", "1qazxsw2",
        // Common words and phrases
        "password", "password1", "password2", "password3", "password12",
        "password123", "password1234", "passwort", "passwort1",
        "iloveyou", "letmein1", "sunshine1", "princess1", "football1",
        "baseball1", "trustno1", "dragon12", "master12", "monkey12",
        "shadow12", "michael1", "jennifer1", "superman1", "batman12",
        "access14", "mustang1", "charlie1", "donald12",
        "whatever1", "nothing1", "welcome1", "welcome123",
        "changeme", "changeme1", "P@ssw0rd", "P@ssword1",
        "p@ssw0rd", "p@ssword1", "pa$$word", "pa$$w0rd",
        "passw0rd", "p4ssword", "p4ssw0rd",
        // Admin/default patterns
        "administrator", "admin123", "admin1234", "admin12345",
        "admin@123", "root1234", "toor1234", "default1",
        "test1234", "guest1234", "user1234",
        // Common names + numbers
        "michael1", "jordan23", "jessica1", "ashley12",
        "thomas12", "daniel12", "andrew12", "william1",
        "matthew1", "robert12", "richard1", "joseph12",
        "charles1", "david123", "james123", "john1234",
        // Sports/entertainment
        "football", "baseball", "basketball", "soccer123",
        "yankees1", "lakers24", "cowboys1", "steelers1",
        "starwars", "starwars1", "pokemon1", "minecraft",
        "minecraft1", "fortnite", "fortnite1",
        // Seasonal/year patterns
        "summer18", "summer19", "summer20", "summer21",
        "summer22", "summer23", "summer24", "summer25",
        "winter18", "winter19", "winter20", "winter21",
        "winter22", "winter23", "winter24", "winter25",
        "spring18", "spring19", "spring20", "spring21",
        "spring22", "spring23", "spring24", "spring25",
        "autumn18", "autumn19", "autumn20", "autumn21",
        "autumn22", "autumn23", "autumn24", "autumn25",
        // Animals
        "butterfly", "elephant1", "dolphin1",
        // Common leet speak
        "dr4g0nb4ll", "h4ck3r12",
        // Router/network defaults
        "hermitshell", "netgear1", "linksys1", "dlink123",
        "motorola1", "comcast1", "spectrum1", "wireless1",
        "internet1", "router12", "firewall1", "security1",
        // Phrases
        "iloveyou1", "iloveyou2", "ihateyou", "ihateyou1",
        "fuckyou1", "asshole1", "letmein12", "openme12",
        "trustno12", "trustme12", "secret12", "private1",
        // Countries / cities
        "newyork1", "london12", "paris123",
        // IT/tech
        "computer1", "internet", "network1", "database1",
        "server12",
        // AbcAbc patterns
        "abcdefgh", "abcd1234", "aabbccdd",
        // More from breach lists
        "aa123456", "abc12345", "a1234567", "a12345678",
        "1a2b3c4d", "q1w2e3r4", "1234qwer", "qwer1234",
        "pass1234", "word1234", "test1234", "1password",
        "2password", "mypassword", "mypassword1", "thepassword",
        "password01", "password99", "master123",
        "access123", "login123", "hello123", "monkey123",
        "dragon123", "shadow123", "sunshine", "sunshine123",
        "princess", "princess123", "charlie123", "donald123",
        "lovely123", "michael123", "jessica123",
        "qwerty1234", "asdfasdf", "zxczxczx",
        "trustno123", "letmein123", "welcome12",
        "superman", "superman123", "batman123", "spiderman",
        "spiderman1",
        // Have I Been Pwned top breached (8+ chars only)
        "samantha", "samantha1", "whatever", "maverick1",
        "alexander", "alexande", "maggie12",
        "amanda12", "diamond1", "tigger12", "pepper12",
        "ginger12", "buster12", "harley12",
        "jackson1", "hunter12", "abigail1",
        "chelsea1", "phoenix1", "freedom1", "freedom123",
        "america1", "patriots",
        // More numeric/symbolic
        "!@#$%^&*", "12345!@#",
        // Swear words (common in breaches)
        "f*ckoff1", "bullshit", "bullshit1",
    ].into_iter().collect()
});

/// Check if a password is in the common passwords list.
/// Performs case-insensitive comparison.
pub fn is_common_password(password: &str) -> bool {
    let lower = password.to_ascii_lowercase();
    COMMON_PASSWORDS.contains(lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_common_passwords() {
        assert!(is_common_password("password"));
        assert!(is_common_password("Password"));
        assert!(is_common_password("PASSWORD"));
        assert!(is_common_password("12345678"));
        assert!(is_common_password("qwerty123"));
        assert!(is_common_password("iloveyou"));
        assert!(is_common_password("admin123"));
        assert!(is_common_password("changeme"));
    }

    #[test]
    fn accepts_non_common_passwords() {
        assert!(!is_common_password("xK9#mPq2vL"));
        assert!(!is_common_password("correct horse battery"));
        assert!(!is_common_password("j4Fz!9wQp#Lm"));
    }
}
