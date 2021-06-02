sudo mn -c

echo -e "\n*********************************" 
echo -e "\n Generating switch programs with a template "
python ../../generate_switch_program_w_template.py --switchname s1 --module all --filename obs_main.up4 --template ../../templates/common_ethernet_template.up4
python ../../generate_switch_program_w_template.py --switchname s2 --module ipv4 --filename obs_main.up4 --template ../../templates/common_ethernet_template.up4
python ../../generate_switch_program_w_template.py --switchname s3  --module ipv6 --filename obs_main.up4 --template ../../templates/common_ethernet_template.up4

echo -e "\n*********************************" 
echo -e "\n Compiling uP4 includes "
${UP4ROOT}/build/p4c-msa -I ${UP4ROOT}/build/p4include -o ipv4.json ipv4.up4
${UP4ROOT}/build/p4c-msa -I ${UP4ROOT}/build/p4include -o ipv6.json ipv6.up4

echo -e "\n*********************************" 
echo -e "\n Compiling uP4 main programs \n"
${UP4ROOT}/build/p4c-msa --target-arch v1model -I ${UP4ROOT}/build/p4include  -l ipv4.json,ipv6.json s1_all_main.up4
${UP4ROOT}/build/p4c-msa --target-arch v1model -I ${UP4ROOT}/build/p4include  -l ipv4.json s2_ipv4_main.up4
${UP4ROOT}/build/p4c-msa --target-arch v1model -I ${UP4ROOT}/build/p4include  -l ipv6.json s3_ipv6_main.up4

echo -e "\n*********************************" 
echo -e "\n Compiling P4 programs "
../../p4c-compile.sh s1_all_main_v1model.p4
../../p4c-compile.sh s2_ipv4_main_v1model.p4
../../p4c-compile.sh s3_ipv6_main_v1model.p4

bold=$(tput bold)
normal=$(tput sgr0)

BMV2_MININET_PATH=${UP4ROOT}/extensions/csa/obs-examples/simple-topo
BMV2_SIMPLE_SWITCH_BIN=${UP4ROOT}/extensions/csa/msa-examples/bmv2/targets/simple_switch/simple_switch

P4_MININET_PATH=${UP4ROOT}/extensions/csa/msa-examples/bmv2/mininet

echo -e "${bold}\n*********************************" 
echo -e "Running Tutorial program: obs_example_v1model${normal}" 
sudo bash -c "export P4_MININET_PATH=${P4_MININET_PATH} ;  \
  $BMV2_MININET_PATH/obs_simple_topo_v1model_sw.py --behavioral-exe $BMV2_SIMPLE_SWITCH_BIN \
  --num-hosts 4 --json1 ./s1_all_main_v1model.json --json2 ./s2_ipv4_main_v1model.json --json3 ./s3_ipv6_main_v1model.json"
echo -e "*********************************\n${normal}" 