use abnf_core::streaming::{is_ALPHA, is_DIGIT, CRLF, SP};
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_while, take_while1, take_while_m_n},
    combinator::{map, map_res, opt, recognize, value},
    multi::{fold_many1, separated_list1},
    sequence::{delimited, preceded, terminated, tuple},
    IResult,
};
use std::collections::HashMap;

use crate::{
    parse::{address::address_literal, base64, Atom, Domain, Quoted_string, String},
    types::{Command, DomainOrAddress, Parameter},
};

pub fn command(input: &[u8]) -> IResult<&[u8], Command> {
    alt((
        helo, ehlo, mail, rcpt, data, rset, vrfy, expn, help, noop, quit,
        starttls,   // Extensions
        auth_login, // https://interoperability.blob.core.windows.net/files/MS-XLOGIN/[MS-XLOGIN].pdf
        auth_plain, // RFC 4616
        xclient,
    ))(input)
}

/// helo = "HELO" SP Domain CRLF
pub fn helo(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((
        tag_no_case(b"HELO"),
        SP,
        alt((
            map(Domain, |domain| DomainOrAddress::Domain(domain.into())),
            map(address_literal, |address| {
                DomainOrAddress::Address(address.into())
            }),
        )),
        CRLF,
    ));

    let (remaining, (_, _, domain_or_address, _)) = parser(input)?;

    Ok((remaining, Command::Helo { domain_or_address }))
}

/// ehlo = "EHLO" SP ( Domain / address-literal ) CRLF
pub fn ehlo(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((
        tag_no_case(b"EHLO"),
        SP,
        alt((
            map(Domain, |domain| DomainOrAddress::Domain(domain.into())),
            map(address_literal, |address| {
                DomainOrAddress::Address(address.into())
            }),
        )),
        CRLF,
    ));

    let (remaining, (_, _, domain_or_address, _)) = parser(input)?;

    Ok((remaining, Command::Ehlo { domain_or_address }))
}

/// mail = "MAIL FROM:" Reverse-path [SP Mail-parameters] CRLF
pub fn mail(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((
        tag_no_case(b"MAIL FROM:"),
        opt(SP), // Out-of-Spec, but Outlook does it ...
        Reverse_path,
        opt(preceded(SP, Mail_parameters)),
        CRLF,
    ));

    let (remaining, (_, _, data, maybe_params, _)) = parser(input)?;

    Ok((
        remaining,
        Command::Mail {
            reverse_path: data.into(),
            parameters: maybe_params.unwrap_or_default(),
        },
    ))
}

/// Mail-parameters = esmtp-param *(SP esmtp-param)
pub fn Mail_parameters(input: &[u8]) -> IResult<&[u8], Vec<Parameter>> {
    separated_list1(SP, esmtp_param)(input)
}

/// esmtp-param = esmtp-keyword ["=" esmtp-value]
pub fn esmtp_param(input: &[u8]) -> IResult<&[u8], Parameter> {
    map(
        tuple((esmtp_keyword, opt(preceded(tag(b"="), esmtp_value)))),
        |(keyword, value)| Parameter::new(keyword, value),
    )(input)
}

/// esmtp-keyword = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
pub fn esmtp_keyword(input: &[u8]) -> IResult<&[u8], &str> {
    let parser = tuple((
        take_while_m_n(1, 1, |byte| is_ALPHA(byte) || is_DIGIT(byte)),
        take_while(|byte| is_ALPHA(byte) || is_DIGIT(byte) || byte == b'-'),
    ));

    let (remaining, parsed) = map_res(recognize(parser), std::str::from_utf8)(input)?;

    Ok((remaining, parsed))
}

/// Any CHAR excluding "=", SP, and control characters.
/// If this string is an email address, i.e., a Mailbox,
/// then the "xtext" syntax [32] SHOULD be used.
///
/// esmtp-value = 1*(%d33-60 / %d62-126)
pub fn esmtp_value(input: &[u8]) -> IResult<&[u8], &str> {
    fn is_value_character(byte: u8) -> bool {
        matches!(byte, 33..=60 | 62..=126)
    }

    map_res(take_while1(is_value_character), std::str::from_utf8)(input)
}

/// rcpt = "RCPT TO:" ( "<Postmaster@" Domain ">" / "<Postmaster>" / Forward-path ) [SP Rcpt-parameters] CRLF
///
/// Note that, in a departure from the usual rules for
/// local-parts, the "Postmaster" string shown above is
/// treated as case-insensitive.
pub fn rcpt(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((
        tag_no_case(b"RCPT TO:"),
        opt(SP), // Out-of-Spec, but Outlook does it ...
        alt((
            map_res(
                recognize(tuple((tag_no_case("<Postmaster@"), Domain, tag(">")))),
                std::str::from_utf8,
            ),
            map_res(tag_no_case("<Postmaster>"), std::str::from_utf8),
            Forward_path,
        )),
        opt(preceded(SP, Rcpt_parameters)),
        CRLF,
    ));

    let (remaining, (_, _, data, maybe_params, _)) = parser(input)?;

    Ok((
        remaining,
        Command::Rcpt {
            forward_path: data.into(),
            parameters: maybe_params.unwrap_or_default(),
        },
    ))
}

/// Rcpt-parameters = esmtp-param *(SP esmtp-param)
pub fn Rcpt_parameters(input: &[u8]) -> IResult<&[u8], Vec<Parameter>> {
    separated_list1(SP, esmtp_param)(input)
}

/// data = "DATA" CRLF
pub fn data(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Data, tuple((tag_no_case(b"DATA"), CRLF)))(input)
}

/// rset = "RSET" CRLF
pub fn rset(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Rset, tuple((tag_no_case(b"RSET"), CRLF)))(input)
}

/// vrfy = "VRFY" SP String CRLF
pub fn vrfy(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((tag_no_case(b"VRFY"), SP, String, CRLF));

    let (remaining, (_, _, data, _)) = parser(input)?;

    Ok((
        remaining,
        Command::Vrfy {
            user_or_mailbox: data,
        },
    ))
}

/// expn = "EXPN" SP String CRLF
pub fn expn(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((tag_no_case(b"EXPN"), SP, String, CRLF));

    let (remaining, (_, _, data, _)) = parser(input)?;

    Ok((remaining, Command::Expn { mailing_list: data }))
}

/// help = "HELP" [ SP String ] CRLF
pub fn help(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((tag_no_case(b"HELP"), opt(preceded(SP, String)), CRLF));

    let (remaining, (_, maybe_data, _)) = parser(input)?;

    Ok((
        remaining,
        Command::Help {
            argument: maybe_data,
        },
    ))
}

/// noop = "NOOP" [ SP String ] CRLF
pub fn noop(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((tag_no_case(b"NOOP"), opt(preceded(SP, String)), CRLF));

    let (remaining, (_, maybe_data, _)) = parser(input)?;

    Ok((
        remaining,
        Command::Noop {
            argument: maybe_data,
        },
    ))
}

/// quit = "QUIT" CRLF
pub fn quit(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::Quit, tuple((tag_no_case(b"QUIT"), CRLF)))(input)
}

pub fn starttls(input: &[u8]) -> IResult<&[u8], Command> {
    value(Command::StartTLS, tuple((tag_no_case(b"STARTTLS"), CRLF)))(input)
}

/// https://interoperability.blob.core.windows.net/files/MS-XLOGIN/[MS-XLOGIN].pdf
///
/// username = 1*CHAR ; Base64-encoded username
/// password = 1*CHAR ; Base64-encoded password
///
/// auth_login_command = "AUTH LOGIN" [SP username] CRLF
///
/// auth_login_username_challenge = "334 VXNlcm5hbWU6" CRLF
/// auth_login_username_response  = username CRLF
/// auth_login_password_challenge = "334 UGFzc3dvcmQ6" CRLF
/// auth_login_password_response  = password CRLF
pub fn auth_login(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((
        tag_no_case(b"AUTH"),
        SP,
        tag_no_case("LOGIN"),
        opt(preceded(SP, base64)),
        CRLF,
    ));

    let (remaining, (_, _, _, maybe_username_b64, _)) = parser(input)?;

    Ok((
        remaining,
        Command::AuthLogin(maybe_username_b64.map(|i| i.to_owned())),
    ))
}

pub fn auth_plain(input: &[u8]) -> IResult<&[u8], Command> {
    let mut parser = tuple((
        tag_no_case(b"AUTH"),
        SP,
        tag_no_case("PLAIN"),
        opt(preceded(SP, base64)),
        CRLF,
    ));

    let (remaining, (_, _, _, maybe_credentials_b64, _)) = parser(input)?;

    Ok((
        remaining,
        Command::AuthPlain(maybe_credentials_b64.map(|i| i.to_owned())),
    ))
}

// ----- 4.1.2.  Command Argument Syntax (RFC 5321) -----

/// Reverse-path = Path / "<>"
pub fn Reverse_path(input: &[u8]) -> IResult<&[u8], &str> {
    alt((Path, value("", tag("<>"))))(input)
}

/// Forward-path = Path
pub fn Forward_path(input: &[u8]) -> IResult<&[u8], &str> {
    Path(input)
}

// Path = "<" [ A-d-l ":" ] Mailbox ">"
pub fn Path(input: &[u8]) -> IResult<&[u8], &str> {
    delimited(
        tag(b"<"),
        map_res(
            recognize(tuple((opt(tuple((A_d_l, tag(b":")))), Mailbox))),
            std::str::from_utf8,
        ),
        tag(b">"),
    )(input)
}

/// A-d-l = At-domain *( "," At-domain )
///          ; Note that this form, the so-called "source
///          ; route", MUST BE accepted, SHOULD NOT be
///          ; generated, and SHOULD be ignored.
pub fn A_d_l(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = separated_list1(tag(b","), At_domain);

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// At-domain = "@" Domain
pub fn At_domain(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((tag(b"@"), Domain));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Mailbox = Local-part "@" ( Domain / address-literal )
pub fn Mailbox(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let parser = tuple((Local_part, tag(b"@"), alt((Domain, address_literal))));

    let (remaining, parsed) = recognize(parser)(input)?;

    Ok((remaining, parsed))
}

/// Local-part = Dot-string / Quoted-string
///               ; MAY be case-sensitive
pub fn Local_part(input: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((recognize(Dot_string), recognize(Quoted_string)))(input)
}

/// Dot-string = Atom *("."  Atom)
pub fn Dot_string(input: &[u8]) -> IResult<&[u8], &str> {
    map_res(
        recognize(separated_list1(tag(b"."), Atom)),
        std::str::from_utf8,
    )(input)
}

// Not used?
/// Keyword = Ldh-str
//pub fn Keyword(input: &[u8]) -> IResult<&[u8], &[u8]> {
//    Ldh_str(input)
//}

// Not used?
/// Argument = Atom
//pub fn Argument(input: &[u8]) -> IResult<&[u8], &[u8]> {
//    Atom(input)
//}

///  xtext = *( xchar / hexchar )
///
///  xchar = any ASCII CHAR between "!" (33) and "~" (126) inclusive,
///        except for "+" and "=".
///
/// ; "hexchar"s are intended to encode octets that cannot appear
/// ; as ASCII characters within an esmtp-value.
///
///  hexchar = ASCII "+" immediately followed by two upper case
///      hexadecimal digits
///
/// When encoding an octet sequence as xtext:
///
/// + Any ASCII CHAR between "!" and "~" inclusive, except for "+" and "=",
///   MAY be encoded as itself.  (A CHAR in this range MAY instead be
///   encoded as a "hexchar", at the implementor's discretion.)
///
/// + ASCII CHARs that fall outside the range above must be encoded as
/// "hexchar".
pub fn xtext(input: &[u8]) -> IResult<&[u8], &str> {
    fn is_char(byte: u8) -> bool {
        let res = byte != '+' as u8 && byte != '=' as u8 && matches!(byte, 33..=126);
        res
    }
    // FIXME: handle the hexchar encoding
    map_res(take_while(is_char), std::str::from_utf8)(input)
}

/// xclient-command = XCLIENT 1*( SP attribute-name"="attribute-value )
/// attribute-name = ( NAME | ADDR | PORT | PROTO | HELO | LOGIN | DESTADDR | DESTPORT )
/// attribute-value = xtext
pub fn xclient(input: &[u8]) -> IResult<&[u8], Command> {
    let attribute_name = map_res(
        alt((
            tag(b"NAME"),
            tag(b"ADDR"),
            tag(b"PORT"),
            tag(b"PROTO"),
            tag(b"HELO"),
            tag(b"LOGIN"),
            tag(b"DESTADDR"),
            tag(b"DESTPORT"),
        )),
        std::str::from_utf8,
    );
    let attributes = fold_many1(
        preceded(SP, tuple((attribute_name, tag(b"="), xtext))),
        HashMap::new(),
        |mut acc: HashMap<String, String>, (key, _, value)| {
            acc.insert(key.to_string(), value.to_string());
            acc
        },
    );
    map(
        terminated(preceded(tag_no_case(b"XCLIENT"), attributes), CRLF),
        |attributes| Command::Xclient { attributes },
    )(input)
}

#[cfg(test)]
mod test {
    use super::{command, ehlo, helo, mail};
    use crate::types::{Command, DomainOrAddress};
    use std::collections::HashMap;

    #[test]
    fn test_ehlo() {
        let (rem, parsed) = ehlo(b"EHLO [123.123.123.123]\r\n???").unwrap();
        assert_eq!(
            parsed,
            Command::Ehlo {
                domain_or_address: DomainOrAddress::Address("123.123.123.123".into()),
            }
        );
        assert_eq!(rem, b"???");
    }

    #[test]
    fn test_helo() {
        let (rem, parsed) = helo(b"HELO example.com\r\n???").unwrap();
        assert_eq!(
            parsed,
            Command::Helo {
                domain_or_address: DomainOrAddress::Domain("example.com".into()),
            }
        );
        assert_eq!(rem, b"???");
    }

    #[test]
    fn test_mail() {
        let (rem, parsed) = mail(b"MAIL FROM:<userx@y.foo.org>\r\n???").unwrap();
        assert_eq!(
            parsed,
            Command::Mail {
                reverse_path: "userx@y.foo.org".into(),
                parameters: Vec::default(),
            }
        );
        assert_eq!(rem, b"???");
    }

    #[test]
    fn test_xclient() {
        let (rem, parsed) = command(b"XCLIENT NAME=name.org ADDR=1.1.1.1\r\n???").unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("NAME".to_string(), "name.org".to_string());
        attributes.insert("ADDR".to_string(), "1.1.1.1".to_string());
        assert_eq!(parsed, Command::Xclient { attributes });
        assert_eq!(rem, b"???");
    }
}
