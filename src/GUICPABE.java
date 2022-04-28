import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

public class GUICPABE {

    private static String pairingParametersFileName;
    private static String pkFileName;
    private static String mskFileName;
    private static String skFileName;
    private static String ctFileName;
    private static String plainFileName;
    private static String[] userAttList;
    private static String data;
    private static String policyFileName;
    private static String lastPath = "~/";


    public static void main(String[] args) {
        createWindow();
    }

    private static void createWindow() {
        JFrame frame = new JFrame("基于树形访问策略的加解密软件");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        createUI(frame);
        frame.setSize(800, 300);
        frame.setResizable(false);
//        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private static void createUI(final JFrame frame){

        JTabbedPane tabbedPane = new JTabbedPane();

        JPanel sysIniPanel = SystemInitialUI(frame);
//        tabbedPane.addTab("系统初始化", new ImageIcon(GUICPABE.class.getResource("images/setup.jpeg")), sysIniPanel,"Tab 1 tooltip");
        tabbedPane.addTab("系统初始化", sysIniPanel);
        tabbedPane.setMnemonicAt(0, KeyEvent.VK_1);

        JPanel keyGenPanel = KeyGenUI(frame);
//        tabbedPane.addTab("生成私钥", new ImageIcon(GUICPABE.class.getResource("images/key.png")), keyGenPanel,"Tab 1 tooltip");
        tabbedPane.addTab("生成私钥", keyGenPanel);
        tabbedPane.setMnemonicAt(1, KeyEvent.VK_2);

        JPanel encPanel = EncryptUI(frame);
//        tabbedPane.addTab("加密文件", new ImageIcon(GUICPABE.class.getResource("images/encrypt.jpeg")), encPanel,"Tab 1 tooltip");
        tabbedPane.addTab("加密文件", encPanel);
        tabbedPane.setMnemonicAt(2, KeyEvent.VK_3);

        JPanel decPanel = DecryptUI(frame);
//        tabbedPane.addTab("解密文件", new ImageIcon(GUICPABE.class.getResource("images/decrypt.jpeg")), decPanel,"Tab 1 tooltip");
        tabbedPane.addTab("解密文件", decPanel);
        tabbedPane.setMnemonicAt(3, KeyEvent.VK_4);

        JPanel helpPanel = helpUI(frame) ;
//        tabbedPane.addTab("帮助", new ImageIcon(GUICPABE.class.getResource("images/help.png")), helpPanel,"Tab 1 tooltip");
        tabbedPane.addTab("帮助", helpPanel);
        tabbedPane.setMnemonicAt(4, KeyEvent.VK_5);

        frame.getContentPane().add(tabbedPane, BorderLayout.CENTER);
    }

    private static JPanel helpUI(final JFrame frame){
        JPanel jp = new JPanel(new FlowLayout());

        JTextArea textArea = new JTextArea( 12, 57
                );
        textArea.append("""
                本软件可实现安全、灵活、高效的数据共享。数据基于一个由多个属性组成的树形访问策略进行加密，解密私钥基于一组属性集合生成。在私钥的属性集合满足访问策略的情况下，可以成功解密密文。使用过程中如有问题请联系：15574831545@163.com。
                """);
        textArea.append("""
                一、软件包含4部分：系统初始化，生成私钥，加密文件，解密文件。
                1.各项功能可以独立执行;
                2.每项中的红色标星部分为必须进行设置。
                """);
        textArea.append("""
                二、系统初始化
                1.用于生成系统公钥和主秘钥；
                2.系统公钥公开发布；
                3.系统主秘钥必须由管理者安全妥善保管；
                4.可以为不同的系统生成不同的公钥和主秘钥对，但二者必须配对使用。
                """);
        textArea.append("""
                三、生成私钥
                1.基于一对系统公钥和主秘钥以及一组属性，生成与该属性集合对应的一个私钥。
                2.用户的每个属性由一个字符串表示（不区分大小写，不能含空格，多个单词可用连字符连接），多个属性之间用英文逗号分隔；
                3.生成的私钥与系统公钥相对应，只能用于解密基于此公钥加密的数据。
                """);
        textArea.append("""
                四、加密文件
                1.基于系统公钥和一个访问树策略对一个数据文件进行加密，密文保存至一个指定文件中；
                2.访问策略建议通过access_tree.html以图形化的方式编辑生成；
                """);
        textArea.append("""
                五、解密文件
                1.基于系统公钥和一个私钥，在私钥的属性满足密文访问树结构的情况下，恢复明文至一个指定文件中；
                2.指定密文文件后，可以导出密文对应的访问树文件，并通过access_tree.html以图形化的方式查看；
                3.指定私钥文件后，可以查看该私钥对应的属性。
                """);
        textArea.append("""
                注意：以上过程中，在一个系统内必须保证所使用的系统公钥、主秘钥保持一致。
                """);

        textArea.setFont(new Font("宋体",Font.PLAIN,14));
        textArea.setLineWrap(true);        //激活自动换行功能
        textArea.setEditable(false);
        JScrollPane scroll = new JScrollPane(textArea);
        scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        // 只需要添加滚动条即可
        jp.add(scroll, BorderLayout.EAST);
//        jp.add(textArea);

        return jp;
    }

    private static JPanel SystemInitialUI(final JFrame frame){
        JPanel jp = new JPanel(new FlowLayout());

        JLabel securityLabel=new JLabel("安全级别（默认为128bits）：");
        JComboBox<String> cmb=new JComboBox<>();    //创建JComboBox
//        cmb.addItem("--请选择--");    //向下拉列表中添加一项
        cmb.addItem("80");
        cmb.addItem("128");
        cmb.addItem("192");
        cmb.addItem("256");
        cmb.setSelectedIndex(1);


        lastPath = "~/Desktop/temp.txt";
        JButton setupButton = new JButton("生成系统公钥和主秘钥");
        setupButton.setPreferredSize(new Dimension(200, 40));
        setupButton.setForeground(Color.BLUE);
        setupButton.addActionListener(e -> {
            JFileChooser pkChooser = new JFileChooser(lastPath);
            pkChooser.setDialogTitle("选择系统公钥保存文件");
            int pkOption = pkChooser.showSaveDialog(frame);
            if(pkOption == JFileChooser.APPROVE_OPTION){
                File file = pkChooser.getSelectedFile();
                pkFileName = file.toString();
                lastPath = file.getParentFile().toString();
            }
            else {
                pkFileName = null;
                return;
            }

            JFileChooser mskChooser = new JFileChooser(lastPath);
            mskChooser.setDialogTitle("选择系统主秘钥保存文件");
            int mskOption = mskChooser.showSaveDialog(frame);
            if(mskOption == JFileChooser.APPROVE_OPTION){
                File file = mskChooser.getSelectedFile();
                mskFileName = file.toString();
                lastPath = file.getParentFile().toString();
            }
            else {
                mskFileName = null;
                return;
            }

            pairingParametersFileName =  "security_params/security_level_" + cmb.getSelectedItem() + "bits.properties";

            CPABE.setup(pairingParametersFileName, pkFileName, mskFileName);
            String infoMessage = String.format("系统公钥已保存至：%s\n系统主秘钥已保存至：%s", pkFileName, mskFileName);
            JOptionPane.showMessageDialog(frame, infoMessage, "系统初始化完成", JOptionPane.PLAIN_MESSAGE);
        });

        jp.add(securityLabel);
        jp.add(cmb);
        jp.add(setupButton);

        return jp;
    }

    private static JPanel KeyGenUI(final JFrame frame){
        JPanel jp = new JPanel(new FlowLayout());

        JButton pkButton = new JButton("选择系统公钥文件*");
        pkButton.setPreferredSize(new Dimension(200, 20));
        pkButton.setForeground(Color.RED);
        JTextField pkTextField = new JTextField(40);
        pkTextField.setEditable(false);
        pkButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser(lastPath);
            fileChooser.setDialogTitle("选择系统公钥文件");
            int option = fileChooser.showOpenDialog(frame);
            if(option == JFileChooser.APPROVE_OPTION){
                File file = fileChooser.getSelectedFile();
                pkFileName = file.toString();
                pkTextField.setText(pkFileName);
                lastPath = file.getParentFile().toString();
            }
        });

        JButton mskButton = new JButton("选择系统主秘钥文件*");
        mskButton.setPreferredSize(new Dimension(200, 20));
        mskButton.setForeground(Color.RED);
        JTextField mskTextField = new JTextField(40);
        mskTextField.setEditable(false);
        mskButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser(lastPath);
            fileChooser.setDialogTitle("选择系统主秘钥文件");
            int option = fileChooser.showOpenDialog(frame);
            if(option == JFileChooser.APPROVE_OPTION){
                File file = fileChooser.getSelectedFile();
                mskFileName = file.toString();
                mskTextField.setText(mskFileName);
                lastPath = file.getParentFile().toString();
            }
        });

        JButton attButton = new JButton("点击输入用户属性*");
        attButton.setPreferredSize(new Dimension(200, 20));
        attButton.setForeground(Color.RED);
        JTextField attTextField = new JTextField(40);
        attTextField.setEditable(false);
        attButton.addActionListener(e -> {
            String result = (String)JOptionPane.showInputDialog(
                    frame,
                    "多个属性之间用英文逗号分隔。比如 A,GroupA,Group-A",
                    "请输入用户属性",
                    JOptionPane.PLAIN_MESSAGE,
                    null,
                    null,
                    "A,B,C"
            );
            if(result != null && result.length() > 0){
                userAttList = result.split(",");
                attTextField.setText(result);
            }
        });

        JButton keyGenButton = new JButton("生成用户私钥");
        keyGenButton.setPreferredSize(new Dimension(200, 40));
        keyGenButton.setForeground(Color.BLUE);
        keyGenButton.addActionListener(e -> {
            if (pkFileName == null) {
                JOptionPane.showMessageDialog(frame, "请先选择系统公钥文件");
                return;
            }
            if (mskFileName == null) {
                JOptionPane.showMessageDialog(frame, "请先选择系统主秘钥文件");
                return;
            }
            if (userAttList == null) {
                JOptionPane.showMessageDialog(frame, "请先输入用户属性");
                return;
            }
            JFileChooser fileChooser = new JFileChooser(lastPath);
            fileChooser.setDialogTitle("选择私钥保存文件");
            int option = fileChooser.showSaveDialog(frame);
            if(option == JFileChooser.APPROVE_OPTION){
                File file = fileChooser.getSelectedFile();
                skFileName = file.toString();
                lastPath = file.getParentFile().toString();
            }
            else {
                skFileName = null;
                return;
            }
            try {
                CPABE.keygen(userAttList, pkFileName, mskFileName, skFileName);
                JOptionPane.showMessageDialog(frame, String.format("用户私钥已保存至：%s", skFileName), "私钥已生成", JOptionPane.PLAIN_MESSAGE);
            } catch (NoSuchAlgorithmException ex) {
                ex.printStackTrace();
            }
        });

        jp.add(pkButton);
        jp.add(pkTextField);
        jp.add(mskButton);
        jp.add(mskTextField);
        jp.add(attButton);
        jp.add(attTextField);
        jp.add(keyGenButton);

        return jp;
    }

    private static JPanel EncryptUI(final JFrame frame){
        JPanel jp = new JPanel(new FlowLayout());

        JButton pkButton = new JButton("选择系统公钥文件*");
        pkButton.setPreferredSize(new Dimension(200, 20));
        pkButton.setForeground(Color.RED);
        JTextField pkTextField = new JTextField(40);
        pkTextField.setEditable(false);
        pkButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser(lastPath);
            fileChooser.setDialogTitle("选择系统公钥文件");
            int option = fileChooser.showOpenDialog(frame);
            if(option == JFileChooser.APPROVE_OPTION){
                File file = fileChooser.getSelectedFile();
                pkFileName = file.toString();
                pkTextField.setText(pkFileName);
                lastPath = file.getParentFile().toString();
            }
        });

        JButton dataButton = new JButton("选择待加密文件*");
        dataButton.setPreferredSize(new Dimension(200, 20));
        dataButton.setForeground(Color.RED);
        JTextField dataTextField = new JTextField(40);
        dataTextField.setEditable(false);
        dataButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser(lastPath);
            fileChooser.setDialogTitle("选择待加密文件");
            int option = fileChooser.showOpenDialog(frame);
            if(option == JFileChooser.APPROVE_OPTION){
                File file = fileChooser.getSelectedFile();
                lastPath = file.getParentFile().toString();
                try {
                    // 将待加密文件中的数据读取data变量中
                    FileInputStream fileInputStream = new FileInputStream(file);
                    byte[] b = new byte[(int) file.length()];  //定义文件大小的字节数据
                    fileInputStream.read(b);//将文件数据存储在b数组
                    data = new String(b, StandardCharsets.UTF_8); //将字节数据转换为UTF-8编码的字符串
                    System.out.println(data);
                    dataTextField.setText(file.toString());
                    fileInputStream.close();          //关闭文件输入流
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        });

        JButton policyButton = new JButton("选择访问策略文件*");
        policyButton.setPreferredSize(new Dimension(200, 20));
        policyButton.setForeground(Color.RED);
        JTextField policyTextField = new JTextField("如尚未构建访问策略，可在浏览器中打开access_tree.html以图形化方式构建。", 40);
        policyTextField.setForeground(Color.gray);
        policyTextField.setEditable(false);
        policyButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser(lastPath);
            fileChooser.setDialogTitle("选择访问策略文件");
            int option = fileChooser.showOpenDialog(frame);
            if(option == JFileChooser.APPROVE_OPTION){
                File file = fileChooser.getSelectedFile();
                policyFileName = file.toString();
                policyTextField.setForeground(Color.BLACK);
                policyTextField.setText(policyFileName);
                lastPath = file.getParentFile().toString();
            }
        });

        JButton encButton = new JButton("加密");
        encButton.setPreferredSize(new Dimension(200, 40));
        encButton.setForeground(Color.BLUE);
        encButton.addActionListener(e -> {
            if (pkFileName == null) {
                JOptionPane.showMessageDialog(frame, "请先选择系统公钥文件");
                return;
            }
            if (data == null) {
                JOptionPane.showMessageDialog(frame, "请先选择待加密文件");
                return;
            }
            if (policyFileName == null) {
                JOptionPane.showMessageDialog(frame, "请先选择访问树文件");
                return;
            }
            JFileChooser fileChooser = new JFileChooser(lastPath);
            fileChooser.setDialogTitle("选择密文保存文件");
            int option = fileChooser.showSaveDialog(frame);
            if(option == JFileChooser.APPROVE_OPTION){
                File file = fileChooser.getSelectedFile();
                ctFileName = file.toString();
                lastPath = file.getParentFile().toString();
            }
            else {
                ctFileName = null;
                return;
            }
            try {
                CPABE.kemEncrypt(data, policyFileName, pkFileName, ctFileName);
                JOptionPane.showMessageDialog(frame, String.format("密文已保存至：%s", ctFileName), "加密已完成", JOptionPane.PLAIN_MESSAGE);
            }
            catch (GeneralSecurityException | IOException ex) {
                ex.printStackTrace();
            }
        });

        jp.add(pkButton);
        jp.add(pkTextField);
        jp.add(dataButton);
        jp.add(dataTextField);
        jp.add(policyButton);
        jp.add(policyTextField);
        jp.add(encButton);

        return jp;
    }

    private static JPanel DecryptUI(final JFrame frame){
        JPanel jp = new JPanel(new FlowLayout());

        JButton ctButton = new JButton("选择待解密密文文件*");
        ctButton.setPreferredSize(new Dimension(200, 20));
        ctButton.setForeground(Color.RED);
        JTextField ctTextField = new JTextField(40);
        ctTextField.setEditable(false);
        ctButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser(lastPath);
            fileChooser.setDialogTitle("选择待解密密文文件");
            int option = fileChooser.showOpenDialog(frame);
            if(option == JFileChooser.APPROVE_OPTION){
                File file = fileChooser.getSelectedFile();
                ctFileName = file.toString();
                ctTextField.setText(ctFileName);
                lastPath = file.getParentFile().toString();
            }
        });

        JButton policyButton = new JButton("导出密文访问策略");
        policyButton.setPreferredSize(new Dimension(200, 20));
        JTextField policyTextField = new JTextField("导出的访问策略可以在浏览器打开access_tree.html后导入以图形化方式查看。", 40);
        policyTextField.setForeground(Color.gray);
        policyTextField.setEditable(false);
        policyButton.addActionListener(e -> {
            if (ctFileName == null) {
                JOptionPane.showMessageDialog(frame, "请先选择待解密文件");
                return;
            }
            JFileChooser fileChooser = new JFileChooser(lastPath);
            fileChooser.setDialogTitle("导出密文访问策略至");
            int option = fileChooser.showSaveDialog(frame);
            if(option == JFileChooser.APPROVE_OPTION){
                File file = fileChooser.getSelectedFile();
                lastPath = file.getParentFile().toString();
                Properties ctProp = CPABE.loadPropFromFile(ctFileName);
                String accessTreeString = ctProp.getProperty("Policy");
                // 将accessTree的json字符串写入用户选择的文件中
                try(PrintWriter out = new PrintWriter(file.toString())) {
                    out.write(accessTreeString);
                    JOptionPane.showMessageDialog(frame, "密文访问策略已保存至： " + file.toString(), "密文策略导出成功", JOptionPane.PLAIN_MESSAGE);
                    policyTextField.setForeground(Color.BLACK);
                    policyTextField.setText("密文访问策略已保存至： " + file.toString());
                } catch (FileNotFoundException ef) {
                    ef.printStackTrace();
                    System.exit(-1);
                }

            }
        });

        JButton skButton = new JButton("选择用户私钥文件*");
        skButton.setPreferredSize(new Dimension(200, 20));
        skButton.setForeground(Color.RED);
        JTextField skTextField = new JTextField(40);
        skTextField.setEditable(false);
        skButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser(lastPath);
            fileChooser.setDialogTitle("选择用户私钥文件");
            int option = fileChooser.showOpenDialog(frame);
            if(option == JFileChooser.APPROVE_OPTION){
                File file = fileChooser.getSelectedFile();
                skFileName = file.toString();
                skTextField.setText(skFileName);
                lastPath = file.getParentFile().toString();
            }
        });

        JButton skAttButton = new JButton("查看用户私钥对应的属性");
        skAttButton.setPreferredSize(new Dimension(200, 20));
        JTextField skAttTextField = new JTextField(40);
        skAttTextField.setEditable(false);
        skAttButton.addActionListener(e -> {
            if (skFileName == null) {
                JOptionPane.showMessageDialog(frame, "请先选择秘钥文件");
                return;
            }
            Properties skProp = CPABE.loadPropFromFile(skFileName);
            String userAttListString = skProp.getProperty("userAttList");
            skAttTextField.setText("私钥对应属性："+ userAttListString);
        });

        JButton decButton = new JButton("解密密文");
        decButton.setPreferredSize(new Dimension(200, 40));
        decButton.setForeground(Color.BLUE);
        decButton.addActionListener(e -> {
            try {

                if (ctFileName == null) {
                    JOptionPane.showMessageDialog(frame, "请先选择待解密文件");
                    return;
                }
                if (skFileName == null) {
                    JOptionPane.showMessageDialog(frame, "请先选择秘钥文件");
                    return;
                }
                String res =CPABE.kemDecrypt(ctFileName, skFileName);
                if (res != null) {
//                        JOptionPane.showMessageDialog(frame, "解密结果为: " + res);
                    JFileChooser fileChooser = new JFileChooser(lastPath);
                    fileChooser.setDialogTitle("选择明文保存文件");
                    int option = fileChooser.showSaveDialog(frame);
                    if(option == JFileChooser.APPROVE_OPTION){
                        File file = fileChooser.getSelectedFile();
                        plainFileName = file.toString();
                        lastPath = file.getParentFile().toString();
                    }
                    else {
                        plainFileName = null;
                        return;
                    }

                    try(PrintWriter out = new PrintWriter(plainFileName)) {
                        out.write(res);
                        JOptionPane.showMessageDialog(frame, String.format("解密结果已保存至：%s", plainFileName),"解密成功", JOptionPane.PLAIN_MESSAGE);
                    } catch (FileNotFoundException ef) {
                        ef.printStackTrace();
                        System.exit(-1);
                    }
                } else {
                    JOptionPane.showMessageDialog(frame, "解密失败");
                }
            } catch (GeneralSecurityException | IOException ex) {
                ex.printStackTrace();
            }
        });

        jp.add(ctButton);
        jp.add(ctTextField);
        jp.add(policyButton);
        jp.add(policyTextField);
        jp.add(skButton);
        jp.add(skTextField);
        jp.add(skAttButton);
        jp.add(skAttTextField);
        jp.add(decButton);

        return jp;
    }
}
