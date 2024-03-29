#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "./randombytes.h"
#include "./sign.h"

#define MLEN 59

int main(void)
{
  unsigned int j;
  int ret;
  size_t mlen;
  uint8_t m[MLEN] = "D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8";
  uint8_t sm[MLEN + CRYPTO_BYTES]="8514E7E52D965C3966052FF4EE66F817CAB304AD677931442993E237B7B1A4757C67CB9313583364CE57FBDAC0F9F1E2781E112A94C2C750007AE1504F9325CB583EA14207E32CE31969AB2E6CB61CCBCAA6AF5A9DC2B92ED093FBF6943772DDC4862CCFDDFB0645FE7563B87376697EB046A82E0D71A3CB0229C1B40FC3230128DE309D3942563A15E14699BCEE7E2579B1ECC757CB07B589C23DB44A66F42117118FE1206F5ABE9EA621A688C08AB31B56B26A977E501E270F78A46F55FE52667C075DAA736BF1DCA889EDF3A85944CDC06C3579647814053767BF064E9F8159B10E82A273118D186662AE93D811E0F2C0AAF5078D6273C069CE0597C35BBBD416624AD2EBFFAACCA0CFD6F7A34CAC9B6CCC78AEE98D3F3FB8CE29AD31DD5594115E79B8A293A28E412005C6668196D689F8027986F2C0D9CF398D850188BCC16F0C697E48CB74061BB769DB86D7C8C37A914B79FD38EDB7C34755F13E70C7F1347F1C5ED3DB23EEE7233E56888F1A571A395600EBD1641A94C0100F90BC91CD7118F1607D2F39CB7ECDCCBE8183B9F31A460CEACFBB204D283B27C24FE08185C1675796BCE87EC64A4D9A79C9FF0CEC36561164F7D69EA9BB5B48DD5E8A46D1A5050B35E34D29CA13A8BF74E0A2C027AEEB69ED6D1EC98A93F4F175B36B41AA5E1E919838B3B19BF8BE57B096F52FFD6B35BB829FB2FBA35FA6D06029C3BB999480D7A2459F2E5BCE85DECAFCB5C2153590A7E1004D8CAFB598E5E8E709990984C82BD8270925F3C965BCDA9A5A7DD125B312078A01AB3F176B2C5C80DC5DD27669E1B7C39C5407E9033C9D84C89335753630348F9433042FBA5E208F4CBC4879A06020B5D0527E8C7880B9415397215B89F89C0782DBF82478011B8F89BD21CDA51404F090BB8379AEF116BFE0D9FCADDA27C0B341B86981021A18E14071B0239989F0026FDEDA101A2EEA5ECA21EE37D5D03BF2C71B384719C0DFE79FFE36DA2D0DDC51CBFDAA61E59EC789A1C549DA6B82BFA22057BD97EEBAAB556F4A70B3751A9F520EA323670A9EB1B785080AFD0133FDE77427FEA9A46F3E277D4EE8070BA015817D852DDDACBE92018C7D3497FCA2E138611B676EB959CDD86572A28F2D28FEE6FD44010EA673E8DFCF44C91C91984FF352817D987EBFB41C6F35FDDBEA92F410834BB899964B669D2A6B61A29CE4667AFEC926AF8C6994412771014AF284C0A5181F890AFAAA2382879453BF3816D6AD071F22080D404D444A34D7C0E16761960CBAA09B900565D5417ED7B545DB5C8AFEBD50B84F270EE5224332EEFB210E83FE259A1294BFD91085F0AD6AD8FB52597918BA4B75175FA3AD51B0D5520698C3FC743E4147821C8FD38F811AA1F49D01EB4101C717FE002E03AF5AA4351DAD62E6B078866F1A8370CD103B5CEE6FC848142180CB7FBE91BA8C2FBD9A1A74F1431C50E6482EDC856D484934EE29ED2AC59B1C46A7BC9356EEAD442C6E4224F95DA5451A11AC5772A61A640C6EEFEAD572FBE7DEDD0F826BB6A66D3B8169BD8F090ADA1E866F801F3F0FD5CC5B92D86213229452D64123574EFBB7287FA396A009463AF64A7320EBC1FCDEE9B4D38ABB32A703E3E901365DCF724B1DC89D6796C71040E0F4C088021A76972CD779C247CA4E472A15B5A95843F6615E67512D0C2A9A0468E7633EF61A6F9FF0A91B35E361B8CFF2DBFBA16C383B31019867BDC1485934B51C29352DD3B7069C887D85823EEC77BDDD2EAB9F4789B228576BB9452159637BBCFD1B1945412409BCCA189C09AAF1C47DA990B2632C857891AFA8D933279DFDF1174B0D3B7CB42F97755EF8A2DD929604E91E2DA24CF97E77AEB37F204003E194F28E74CCD594728324B40B863F239AB8A66D675FC4026B80ABD49B8A896755AE72758E8851CBE755A649BE9B9B14B6C83B1898C3BE2232CA3B784051A0E4C75A2284B92B07A0F0AF926FF852C0043C37F698DD25B26B3548CBA59B8841AA30C1EA17C61E2003A2772A29C16887943CBB383700361522CBA5D6C5AA2F3AEAD49908AEAFBBC3AD4E45B35E1780397CC67B4546AB16162CBF24408A5BFB4782357BE47B11CCC1D0735F057BE5BC5BCDE5B5B7E2F1305527D33A0C117555D8B61FB42A49A024C5D76B61020F5D8C117D6FACE209765F741BB4246FE6F03C248241915FBFC30C44F2865E545941A559A38059A0128FED386F2D2F5B07B9F15A9D4F499577F9B5BA5654EBD963BA3329A09B2938C58B88AC61ACFD3F8636E62CBEA73D53645E3032FD1C5C832BA9FD92DD5F7556C7E38542E3A91632E5B3BC52A01E553ACA19D122A4DB7A06511CD0C10934DB1454CAF05EDA88A81C02D759D444E636AA876757BED5092189C14079038FE07E1FB98B72437A202B2924E39B7047A68B9F8C2138F1ED679D412729AFD9ACC5B7A33D5D053F5ADADF3FF7E75D767D142B7D0ACAE0A67EB5126F47A64A0EB2F3EA9D219D9B3AB37FBDC79A332B8A005D3CA872358CB2728CE7A213A0B999C6DA5D528F2A7AC85E89501F695F5920F3F33D2DB69DB1DA3921E7ECF11F90DFA7363D0D61EFDD4417BCFAA4111C52D94A7DEE6D5D8E0FD6D20BF0ADAB7096DDBD0071167B55F322B9840D1EFF8646730F35BECD8A5B4A33E0722A0880F1CDC868387EC3D740F9A584C7BF444D334D32D41A71A27E68608B525CC2347A1D9A5D37AF561DDA339D864D5803018D9094D59C20A8ECC508A42E43B022859AADE550A515C8CF600717CB0008941E78C4350B03CA8208E1DF90F9F563A6AB0B98006A523F542AD10B40A81DD5F57142AF266FB9C49FF07D2E5D5580673A8FB53F6E0ADAE3383DCC1B839130B9D1B82A8E26B2B60613327C09C9ABA56AB86B138D35BEBBC3FA861DBB88AC5502BDFF8F05B72B0A7C302EB95F8B9F703C48576D3EAA3F00342821D4AC816452598E76F094D15D3FA7EFF56DDE0E7F500EE7FD6EA9AC3FD119581BEB53BE002434475F8D99AFFF2CFD0FB07006C0CCE41F4A7F8424B68628FC788D78960A30AFEB4F6EE45C1F3C0F2129F419F953E241DEBF242DD8C168ED26012E5D2508DB7BD9060969D603862BEE4233E3EEA7CCC1AC8C2606A6C6EA5DAA9C6CEDD86BAE90E3A943A39568D335045639F91B0118F58473E51C29D1217480C364034F1CCBEAD53512DF42BB732763FCAE37D7776AF5E8D44AFCC8B6B7CA547CDD800598919388A0FF42034A678E83556292B8593ED37EE324271FBCCCC1ABF93216CA332E36F77C4F75FE7D8BBE87B0C59B9B6696DFAA4C825EC15C088B1EBB3C557027AD81044142546B788DA0ACCCE3EBF9FC272F30474A4B8586C7DAEFF2F5FC020309172B476877979C9DC2C3C5D7DEE5F2F9032C2F365A5E696B7B809AAAB5B7B9CFFE000000000000000000000000000000000E1C2F40D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8";
  uint8_t pk[CRYPTO_PUBLICKEYBYTES]="1C0EE1111B08003F28E65E8B3BDEB037CF8F221DFCDAF5950EDB38D506D85BEFEA58E9EA74E74E865732B2AC3430BF90C4AA8FDCC4AA33BE606137070424B0FBA4A11A501E20EC68FC58ECE335F9AE78F1E923B03BBC685CD35AC30DE2F13D9FEFD7BE78D61BA06673D86462A139AD2B3D662E5A60AB333B81E5800D6D31ED99A82458839849E0ECC9C6DF32FFFCF24A650D333FC770204C4ACBB65A2494324326084798FCCA8E741C69787E40EAEE8DCA0C2092CAC715243AB515EE0097467729E6DC89FBB0875F7F8731EB050D16519D2F9F8F08B9AB180AD06FAE9CC7F7FE68A6967F471295C9690230CA0DC75C867AE4AC2C074886B6B2C1DD1549863B351A63606659C12C064C943786827D6DB2A6A523246EB2E4BEE9E02487FAE204A8192D8B777D1BED4B1C5D79813D6A43667A8819D2DFED21BE3990487533E76A87839ECADEB8CBF5EA53E32E2A8621691C14BBC22A5A96EB4D6E7160BADCE8F316D740763FDBBCB988AE8CDA04138AA1843C22BA09F47CBC619899DB6B89816C0BCDD6D3E323B621B3DBC062B0870B4657906A9CEA5F710CC0A0518CE707BF001B13D49582DAC49036659FCAFC8DF6B543E77C43B9A8AF064EA8DF85180EF9603696F4B9B8E4C8F0F49FFF35C3D5A7ABB187D290EA31B39024123DBAEA32863983C158B93E3A377A7C8B7869D364108A743E9577F1301BFBD4243D8A4107A96F412B1B82CDBA108DC3F6F451EDB118B9858A6E941F6562B86340C8D3A73066DB069B5B4598542457CAA7D284C0F6B0BB760F8FABBFC4CDAB8F093FAC2685E571C1F9EAC2521620DB589236B14FE225629FC7B6A491BA140422C428022EAD784A7412758FA562AFEB321F074F7151C0A745D2E7FC0D58B8972A348D18A8BB37242E011635EEF22584E3E2D3B1CF0327A2BEA4D28700E8D6D8B1AE80950B5ECBD03E6ECFD108CD7864F9D86AB330C0D76A105DF8577A65A66B591D062349D1D2A85256201CBB0AD9D6BF33EBE0A8AB88CC510750F3BC86BF4EA117B45118996E1D6E295A2F6F606DB7B6BEF17994519ACB15D0EEA565EF8143AACDB4D4F8FF5770FFCCEF6801E016A9D221EA165C4DA13E8B3FC562E04788D606328186F15CF74B47DACF24DC05EEFEB13016BBFA6F05D551B5110572F749E9F68A35E14F87C4B03E1FC58036E93EF13194879D01CDBD2D5AD4250CE3F213C88BADCB009314F4D69D25D6EB24794964FD47767CF8457AC2652D6FFAF0F1542B51AA56B5A8A474BCC61B99DE8391B211EB900EFE7EB82DB3B5800B8A914B9BC9305DC590C039CC2AC3BB445197C1FCF131353B6120D9A8697BEDF3D2306B511EDE9CC00344C42155F9E30208121FD7C4FBDFB200133A1D27A735D55FC05EEFE9E6D6C4D5BAD0A6F61FC756E6F939FA3380EE34318A14352AF86E7A9ED05748A281093CBDF7FC41973D4A52EDCE691BF5E28BE6382C41512AEBDCE0DBBD46FC8FFEF7005B8C975A7A08D38B98FFAF2BD08D38F72921B2CC4241AD2E692B14E1467907DA4289EF8D96396A1FAF508703A7E7634F08B55852B3975A4FD16684017B21ECF99BBFEDABF3C3F9A70F051C5FE04804EBCABDDC9E96F6C741E4215726767FE2039F47F3FCDA8069C6AE040EDDC74541A638585D431943D987ABECC9B243942E84CD76C004FB73EB7C3E288FFE70DE48E9C3B3F83B6FFA1DB0EDCFE22CB23DDEFC5C123800F8F9B63B5079A201A32B4C8B9005F79F911A94766F55E0778679C6BEA7E0E0AA3F167A0548CCF48C42947D6A8C18C63A5BF6FE910588275985567092A6240ECB1B058C815E866ABEB6CF2E34ABA6E4ABAFF35AF1E59FAC1257AB14DC6B6C0A6DC578";
  uint8_t m2[MLEN + CRYPTO_BYTES];
  ret = crypto_sign_open(m2, &mlen, sm, MLEN + CRYPTO_BYTES, pk);
  if(ret) {
    fprintf(stderr, "Verification failed\n");
    return -1;
  }
  if(mlen != MLEN) {
    fprintf(stderr, "Message lengths don't match\n");
    return -1;
  }

  for(j = 0; j < mlen; ++j) {
    if(m[j] != m2[j]) {
      fprintf(stderr, "Messages don't match\n");
      return -1;
    }
  }
	return 0;
}
