import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.apache.commons.io.FileUtils;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class CPABE {

    public static void setup(String pairingParametersFileName, String pkFileName, String mskFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element g = bp.getG1().newRandomElement().getImmutable();
        Element alpha = bp.getZr().newRandomElement().getImmutable();
        Element beta = bp.getZr().newRandomElement().getImmutable();

        Element g_alpha = g.powZn(alpha).getImmutable();
        Element g_beta = g.powZn(beta).getImmutable();
        Element egg_alpha = bp.pairing(g,g).powZn(alpha).getImmutable();

        Properties mskProp = new Properties();
        mskProp.setProperty("g_alpha", Base64.getEncoder().withoutPadding().encodeToString(g_alpha.toBytes()));

        Properties pkProp = new Properties();
        pkProp.setProperty("g", Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));
        pkProp.setProperty("g_beta", Base64.getEncoder().withoutPadding().encodeToString(g_beta.toBytes()));
        pkProp.setProperty("egg_alpha", Base64.getEncoder().withoutPadding().encodeToString(egg_alpha.toBytes()));
        pkProp.setProperty("ppFile", pairingParametersFileName);

        storePropToFile(mskProp, mskFileName);
        storePropToFile(pkProp, pkFileName);
    }

    public static void keygen(String[] userAttList, String pkFileName, String mskFileName, String skFileName) throws NoSuchAlgorithmException {
        Properties pkProp = loadPropFromFile(pkFileName);
        Pairing bp = PairingFactory.getPairing(pkProp.getProperty("ppFile"));

        String gString = pkProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String g_betaString = pkProp.getProperty("g_beta");
        Element g_beta = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g_betaString)).getImmutable();

        Properties mskProp = loadPropFromFile(mskFileName);
        String g_alphaString = mskProp.getProperty("g_alpha");
        Element g_alpha = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g_alphaString)).getImmutable();

        Properties skProp = new Properties();

        Element t = bp.getZr().newRandomElement().getImmutable();
        Element D = g_alpha.mul(g_beta.powZn(t)).getImmutable();
        Element D0 = g.powZn(t);

        skProp.setProperty("D", Base64.getEncoder().withoutPadding().encodeToString(D.toBytes()));
        skProp.setProperty("D0", Base64.getEncoder().withoutPadding().encodeToString(D0.toBytes()));

        for (String att : userAttList) {
            byte[] idHash = sha256(att.toLowerCase(Locale.ROOT));
            Element H = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();
            Element Datt = H.powZn(t).getImmutable();
            skProp.setProperty("D-"+att.toLowerCase(Locale.ROOT), Base64.getEncoder().withoutPadding().encodeToString(Datt.toBytes()));
        }

        skProp.setProperty("userAttList", Arrays.toString(userAttList).toLowerCase(Locale.ROOT));
        storePropToFile(skProp, skFileName);
    }

    public static void kemEncrypt(String data, String policyName,
                               String pkFileName, String ctFileName) throws GeneralSecurityException, IOException {
        File file=new File(policyName);
        String accessTreeString= FileUtils.readFileToString(file,"UTF-8");
        Map<String, TreeNode> accessTree = jsonStringToAccessTree(accessTreeString);


        Properties pkProp = loadPropFromFile(pkFileName);
        Pairing bp = PairingFactory.getPairing(pkProp.getProperty("ppFile"));
        String gString = pkProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String g_betaString = pkProp.getProperty("g_beta");
        Element g_beta = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g_betaString)).getImmutable();
        String egg_alphaString = pkProp.getProperty("egg_alpha");
        Element egg_alpha = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(egg_alphaString)).getImmutable();

        Properties ctProp = new Properties();
        //计算密文组件 C=M e(g,g)^(alpha s)
        Element s = bp.getZr().newRandomElement().getImmutable();
        Element randomGT = bp.getGT().newRandomElement().getImmutable();
        Element C = randomGT.duplicate().mul(egg_alpha.powZn(s)).getImmutable();
        Element C0 = g.powZn(s).getImmutable();

        // 将随机的GT元素导出为对称秘钥
        byte[] symmetricKey = sha256(randomGT.toBytes());
        // 使用对称秘钥进行对称加密
        byte[] symmetricCp =  AES.encrypt(symmetricKey, data.getBytes(StandardCharsets.UTF_8));
        // 保存对称密文
        ctProp.setProperty("symmetricCp", Base64.getEncoder().withoutPadding().encodeToString(symmetricCp));

        ctProp.setProperty("C", Base64.getEncoder().withoutPadding().encodeToString(C.toBytes()));
        ctProp.setProperty("C0", Base64.getEncoder().withoutPadding().encodeToString(C0.toBytes()));

        //先设置根节点要共享的秘密值，根节点的name值固定为0
        accessTree.get("0").secretShare = s;
//        进行共享，使得每个叶子节点获得相应的秘密分片
        nodeShare(accessTree, "0", bp);

        for (String key : accessTree.keySet()) {
            TreeNode node = accessTree.get(key);
            if (node.isLeaf()){
                Element r = bp.getZr().newRandomElement().getImmutable();

                byte[] idHash = sha256(node.att);
                Element Hi = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();

                Element C1 = g_beta.powZn(node.secretShare).mul(Hi.powZn(r.negate()));
                Element C2 = g.powZn(r);

                ctProp.setProperty("C1-"+node.att, Base64.getEncoder().withoutPadding().encodeToString(C1.toBytes()));
                ctProp.setProperty("C2-"+node.att, Base64.getEncoder().withoutPadding().encodeToString(C2.toBytes()));
            }
        }
        // 将策略字符串保存在密文当中
        ctProp.setProperty("Policy", accessTreeString);
        // 将所用的公共参数文件写入密文中，使得解密的时候不需要公钥，只需要密文和私钥
        ctProp.setProperty("ppFile", pkProp.getProperty("ppFile"));
        storePropToFile(ctProp, ctFileName);
    }

    public static String kemDecrypt(String ctFileName, String skFileName) throws GeneralSecurityException, IOException {
        Properties ctProp = loadPropFromFile(ctFileName);
        Pairing bp = PairingFactory.getPairing(ctProp.getProperty("ppFile"));

        Properties skProp = loadPropFromFile(skFileName);
        String userAttListString = skProp.getProperty("userAttList");
        //恢复用户属性列表String[]类型：先将首尾的方括号去除，然后按","分割
        String[] userAttList = userAttListString.substring(1, userAttListString.length()-1).split(", ");

        String CString = ctProp.getProperty("C");
        Element C = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(CString)).getImmutable();
        String C0String = ctProp.getProperty("C0");
        Element C0 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C0String)).getImmutable();

        String DString = skProp.getProperty("D");
        Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(DString)).getImmutable();
        String D0String = skProp.getProperty("D0");
        Element D0 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(D0String)).getImmutable();


        // 从密文中获取访问策略字符串
        String accessTreeString = ctProp.getProperty("Policy");
        // 从访问策略字符串构建访问树对象
        Map<String, TreeNode> accessTree = jsonStringToAccessTree(accessTreeString);

        for (String key : accessTree.keySet()) {
            if (accessTree.get(key).isLeaf()) {
                // 如果叶子节点的属性值属于属性列表，则将属性对应的密文组件和秘钥组件配对的结果作为秘密值
                if (Arrays.asList(userAttList).contains(accessTree.get(key).att)){
                    String C1tring = ctProp.getProperty("C1-"+accessTree.get(key).att);
                    Element C1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1tring)).getImmutable();
                    String C2tring = ctProp.getProperty("C2-"+accessTree.get(key).att);
                    Element C2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C2tring)).getImmutable();

                    String DattString = skProp.getProperty("D-"+accessTree.get(key).att);
                    Element Datt = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(DattString)).getImmutable();

                    accessTree.get(key).secretShare = bp.pairing(C1,D0).mul(bp.pairing(C2,Datt)).getImmutable();
                }
            }
        }

        Element randomGT;
        // 进行秘密恢复
        boolean treeOK = nodeRecover(accessTree, "0", userAttList, bp);
        if (treeOK) {
            Element egg_alphas = bp.pairing(C0,D).div(accessTree.get("0").secretShare);
            randomGT = C.div(egg_alphas);
        }
        else {
//            System.out.println("The access tree is not satisfied.");
            return null;
        }

        // 获取对称密文
        byte[] symmetricCp = Base64.getDecoder().decode(ctProp.getProperty("symmetricCp"));
        // 由恢复的GT元素导出对称秘钥
        byte[] symmetricKey = sha256(randomGT.toBytes());
        // 对称解密
        byte[] dataBytes =  AES.decrypt(symmetricKey, symmetricCp);

        return new String(dataBytes, StandardCharsets.UTF_8);
    }

    //d-1次多项式表示为q(x)=coef[0] + coef[1]*x^1 + coef[2]*x^2 + coef[d-1]*x^(d-1)
    //多项式的系数的数据类型为Zr Element，从而是的后续相关计算全部在Zr群上进行
    //通过随机选取coef参数，来构造d-1次多项式q(x)。约束条件为q(0)=s。
    public static Element[] randomP(int d, Element s, Pairing bp) {
        Element[] coef = new Element[d];
        coef[0] = s;
        for (int i = 1; i < d; i++){
            coef[i] = bp.getZr().newRandomElement().getImmutable();
        }
        return  coef;
    }
    //计算由coef为系数确定的多项式qx在点index处的值，注意多项式计算在群Zr上进行
    public static Element qx(Element index, Element[] coef, Pairing bp){
        Element res = coef[0].getImmutable();
        for (int i = 1; i < coef.length; i++){
            Element exp = bp.getZr().newElement(i).getImmutable();
            //index一定要使用duplicate复制使用，因为index在每一次循环中都要使用，如果不加duplicte，index的值会发生变化
            res = res.add(coef[i].mul(index.duplicate().powZn(exp)));
        }
        return res;
    }
    //拉格朗日因子计算 i是集合S中的某个元素，x是目标点的值
    public static Element lagrange(int i, int[] S, int x, Pairing bp) {
        Element res = bp.getZr().newOneElement().getImmutable();
        Element iElement = bp.getZr().newElement(i).getImmutable();
        Element xElement = bp.getZr().newElement(x).getImmutable();
        for (int j : S) {
            if (i != j) {
                //注意：在循环中重复使用的项一定要用duplicate复制出来使用
                //这儿xElement和iElement重复使用，但因为前面已经getImmutable所以可以不用duplicate
                Element numerator = xElement.sub(bp.getZr().newElement(j));
                Element denominator = iElement.sub(bp.getZr().newElement(j));
                res = res.mul(numerator.div(denominator));
            }
        }
        return res;
    }

    // 共享秘密
    // nodes是整颗树的所有节点，n是要分享秘密的节点
    public static void nodeShare(Map<String, TreeNode> accessTree, String n, Pairing bp){
        // 如果是叶子节点，则不需要再分享
        if (!accessTree.get(n).isLeaf()){
            // 如果不是叶子节点，则先生成一个随机多项式，多项式的常数项为当前节点的秘密值（这个值将被用于分享）
            // 多项式的次数，由节点的gate对应的threshold决定
            Element[] coef = randomP(accessTree.get(n).gate[0], accessTree.get(n).secretShare, bp);
            for (int j=0; j<accessTree.get(n).children.length; j++ ){
                // 父节点的children数组中存储的子节点的id是int类型，但从map中取子节点的时候要将int类型转换为String类型
                int childID = accessTree.get(n).children[j];
                String childName = Integer.toString(childID);
                // 对于每一个子节点，以子节点的索引为横坐标，计算子节点的多项式值（也就是其对应的秘密分片）
                accessTree.get(childName).secretShare = qx(bp.getZr().newElement(childID), coef, bp);
                // 递归，将该子节点的秘密继续共享下去
                nodeShare(accessTree, childName, bp);
            }
        }
    }

    // 恢复秘密
    public static boolean nodeRecover(Map<String, TreeNode> accessTree, String n, String[] atts, Pairing bp) {
        if (!accessTree.get(n).isLeaf()) {
            // 对于内部节点，维护一个子节点索引列表，用于秘密恢复。
            List<Integer> validChildrenList = new ArrayList<>();
            int[] validChildren;
            // 遍历每一个子节点
            for (int j=0; j<accessTree.get(n).children.length; j++){
                int childID = accessTree.get(n).children[j];
                String childName = Integer.toString(childID);
                String s = accessTree.get(childName).isLeaf()? accessTree.get(childName).att : Arrays.toString(accessTree.get(childName).gate);
                // 递归调用，恢复子节点的秘密值
                if (nodeRecover(accessTree, childName, atts, bp)){

//                    System.out.println("The node with index " + childName + ": " + s  + " is satisfied!");

                    validChildrenList.add(accessTree.get(n).children[j]);
                    // 如果满足条件的子节点个数已经达到门限值，则跳出循环，不再计算剩余的节点
                    if (validChildrenList.size() == accessTree.get(n).gate[0]) {
                        accessTree.get(n).valid = true;
                        break;
                    }
                }
                else {
//                    System.out.println("The node with index " + childName + ": " + s  + " is not satisfied!");
                }
            }
            // 如果可恢复的子节点个数等于门限值，则利用子节点的秘密分片恢复当前节点的秘密。
            if (validChildrenList.size() == accessTree.get(n).gate[0]){
                validChildren = validChildrenList.stream().mapToInt(i->i).toArray();
                // 利用拉格朗日差值恢复秘密
                // 注意，此处是在指数因子上做拉格朗日差值
                Element secret = bp.getGT().newOneElement().getImmutable();
                for (int i : validChildren) {
                    Element delta = lagrange(i, validChildren, 0, bp);  //计算拉格朗日插值因子
                    secret = secret.mul( accessTree.get(Integer.toString(i)).secretShare.duplicate().powZn(delta) ); //基于拉格朗日因子进行指数运算，然后连乘
                }
                accessTree.get(n).secretShare = secret;
            }
        }
        else {
            // 判断叶子节点的属性值是否属于属性列表
            // 判断一个String元素是否属于String数组，注意String类型和int类型的判断方式不同
            if (Arrays.asList(atts).contains(accessTree.get(n).att)){
                accessTree.get(n).valid = true;
            }
        }
        return accessTree.get(n).valid;
    }

    public static void storePropToFile(Properties prop, String fileName){
        try(FileOutputStream out = new FileOutputStream(fileName)){
            prop.store(out, null);
        }
        catch (IOException e) {
            e.printStackTrace();
//            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)){
            prop.load(in);
        }
        catch (IOException e){
            e.printStackTrace();
//            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }

    public static byte[] sha256(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-256");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static byte[] sha256(byte[] content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-256");
        instance.update(content);
        return instance.digest();
    }


    // 将字符串形式的访问树转换为映射结构
    public static Map<String, TreeNode> jsonStringToAccessTree(String accessTreeString) {
        JSONObject jsonObject=new JSONObject(accessTreeString);
        Map<String, TreeNode> map = new HashMap<>();
        jsonToTree(jsonObject, map);
        return  map;
    }

    public static void jsonToTree(JSONObject obj, Map<String, TreeNode> map) {
        String id = Integer.toString(obj.getInt("name"));
        if (obj.has("children") && obj.getJSONArray("children").length()>0 ) {
            int len = obj.getJSONArray("children").length();
            int[] children = new int[len];
            for (int i =0; i<len; i++) {
                JSONObject o = obj.getJSONArray("children").getJSONObject(i);
                jsonToTree(o, map);
                children[i] = o.getInt("name");
            }
            String gateString = obj.getString("value");
            int t = Integer.parseInt(gateString.split(",")[0].substring(1));
            int n = Integer.parseInt(gateString.split(",")[1].substring(0, gateString.split(",")[1].length()-1));
            int[] gate = new int[]{t, n};
            map.put(id, new TreeNode(gate, children));
        }
        else {
            String att = obj.getString("value");
            map.put(id, new TreeNode(att));
        }
    }
}
