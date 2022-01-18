
**Policies in ec2**

bound: `100`, variables: `True`, constraints: `True`, smt-lib: `False`

|Policy|SAT/UNSAT|Solve Time (ms)|lg(tuple)|Count Time (ms)|lg(principal)|lg(action)|lg(resource)|
|-|-|-|-|-|-|-|-|
|[../samples/ec2/exp_single/ec2_prevent_running_classic/policy.json](../samples/ec2/exp_single/ec2_prevent_running_classic/policy.json)|SAT|33911.9|79901967274088618835884399877532848851858087758982160979762689366393598675948263818744011334277296518448276923378676492220732603415880397532209484654868309416136276258815428166087880449086824047706653136891816462006755005208051577335589970475647147184594299199053826489943665774610432220062846032017543497236814773909798759911994123990778605296183464410938891152187061239808|55.1102|1|1|9591560252848587427279621438095045291204458969771840560549734193093328682007770330532639808458584117097|
|[../samples/ec2/exp_single/ec2_require_mfa_session_token/policy.json](../samples/ec2/exp_single/ec2_require_mfa_session_token/policy.json)|SAT|313860|13044784673393892504628806244664671912978152304923516077320812850293184395875583571418337331146894526286564811341324797542400|10601.1|1|399|13044784673393892504628805538882150191646641221000238252993283799794540444951259369884558955771834437966122711444127224012800|
|[../samples/ec2/exp_single/ec2_launch_instance_specific_subnet/policy.json](../samples/ec2/exp_single/ec2_launch_instance_specific_subnet/policy.json)|SAT|50553.7|13044784673392140669303391935807768381067879489272099335138936621669090866833035547934443129912239526897484004484776935219200|1123.05|1|112|13044784673392140669303391935807768381067879489272099335138936621669090866833035547733884869941590224610807140984776935219200|
|[../samples/ec2/exp_single/ec2_allow_ebs_volume_owners/policy.json](../samples/ec2/exp_single/ec2_allow_ebs_volume_owners/policy.json)|SAT|30668.8|53542679360178965943607616823720223045984670081874207373863146445639341178157952733801562314500596142517719618822130988816194351453597349739013207899847771433776494117362746624684534023141510298230739740427995682294800056320000000000000|139.234|1|2|401116519941298604573353574400000000000000|
|[../samples/ec2/exp_single/ec2_limit_ebs_volume_size/fixed.json](../samples/ec2/exp_single/ec2_limit_ebs_volume_size/fixed.json)|SAT|52509.1|217337728293237770179679568422664827656697772338961517892479367972677099907069394098304776274641113515916816239632075629121295527821987448810438851238108252632889703594933293285218665282522102348985503878539305965781710900943451610121661209233709480909469408009252945294028542365980774728681111396683210646824517291172420760027106773315230593628628096248782584997753645863275000011279285593571328|536.786|1|7|26089569346784306727524543720902660542243387185800079389156331764830802314387632251968979040147640841990133286275127224013502|
|[../samples/ec2/exp_single/ec2_limit_ebs_volume_size/initial.json](../samples/ec2/exp_single/ec2_limit_ebs_volume_size/initial.json)|SAT|44352.3|217337728293237770179679568422664827656697772338961517892479367972677099907069394098304776274641113515916816239630733059335953977906333942041880530981696677914081498823917743716039267529440407771286534043992046899851122184471334587999866070005377274797167649789564856289309568703529351845907249826130127452167204671528708009725252398989926823921631169752798758740263557092043195718159285593571328|347.024|1|7|26089569346784306727524543720902660542243387185800079389156331764830802314387632251968979040147640841990133286275127224013502|
|[../samples/ec2/exp_single/ec2_restrict_to_specific_instance/policy.json](../samples/ec2/exp_single/ec2_restrict_to_specific_instance/policy.json)|SAT|47994.3|23237287185733560567669484036670502445669698900561621539308750528999089193564660435164407819209824731295421534918292542517402182110811035781051011344813708963959241081231771534748549120000000000000|1076.8|1|109|700000000000000|
|[../samples/ec2/exp_single/ec2_enforce_project_tagging/policy.json](../samples/ec2/exp_single/ec2_enforce_project_tagging/policy.json)|SAT|84259.2|108668864146638871944209996356755492658574069634098451733968450567675370188053195860142413292104220927613364533802597629137339452673112449124492046666265796552488273075179026234888315881439023488907139974501212033341535221894268405154042278870489197709950458973060122829235096958403485398722979892469846703058998089409741084581968977514394405920137335961772159084071449764223503393046227075465216|2926.52|1|162|13044784673393917893623850456384484362435321917639957029654320511343501074044452634150753325050816594582162038145127224013502|
|[../samples/ec2/exp_single/ec2_actions_region_aws-portal/policy.json](../samples/ec2/exp_single/ec2_actions_region_aws-portal/policy.json)|SAT|464724|448862752691429177364782015455529668392505184710990672893259785863646851546969051103892890811329296866766239071517336245780974215695887284341384788209460611217777203137291556833468434150331168269408231756721330369581636892868252866043474881575831401457332495105586510630352970464216989758800527693782232466263907755520694175194359935480955360880806548815572192343097640044841928897649333427913277795849604594106240646741983407619267670678852629616565094438691756745800358395904|18390.1|1|446|4442553804447357144871360394135670060853991746751940321559949045066888766816306702623942945660492355798762160554075646239721518372325410643771196536311479036038218128422088053461765722738617234505566474065|
|[../samples/ec2/exp_single/ec2_validate_attach_volume/policy.json](../samples/ec2/exp_single/ec2_validate_attach_volume/policy.json)|UNSAT|26949|-|-|-|-|-|
|[../samples/ec2/exp_single/ec2_terminate_instance_ip/policy.json](../samples/ec2/exp_single/ec2_terminate_instance_ip/policy.json)|SAT|34162.4|102886387364943092073065191833600000000000000|68.3193|1|1|200558259970649302286676787200000000000000|
|[../samples/ec2/exp_single/ec2_allow_some_instances/fixed.json](../samples/ec2/exp_single/ec2_allow_some_instances/fixed.json)|SAT|35479.3|108668864146633372907560734823431695689269112871227272085671335384860929993549579520359566051271860335271223646728461884831033845111035778056343410559051256666899001439920891055746221782645846385470981162072228688747096656114501823108021255216569009023447406725893727567252680863534347692479822349191769432199992459332162667764695415818729388324097630385738699386115200262206456629757370496450560|249.611|1|17|13044784673393892504628805303621309617869470859692478978217411224161216407113555099892988538851695541808741311177063612006400|
|[../samples/ec2/exp_single/ec2_allow_some_instances/initial.json](../samples/ec2/exp_single/ec2_allow_some_instances/initial.json)|SAT|32372|13044784673393892504628805303621309617869470859692478978217411224161216407113555100294105058792994146382094884877063612006400|42.6868|1|3|13044784673393892504628805303621309617869470859692478978217411224161216407113555099892988538851695541808741310477063612006400|