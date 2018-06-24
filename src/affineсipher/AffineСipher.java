/*
 *****************************
  Компьютерный практикум №3
  ФИ-52, Ершов С., Овчарова М.
 *****************************
 */

package affineсipher;
import java.io.*;
import java.util.*;

public class AffineСipher {
    
    private static final String PATH = "D:\\Programming\\Crypt\\AffineCipher\\text\\1.txt";
    private static final String PATH_TO_C = "D:\\Programming\\Crypt\\AffineCipher\\text\\ciphertext.txt";
    private static final String PATH_TO_WRITE = "D:\\Programming\\Crypt\\AffineCipher\\text\\plaintext.txt";
    private static final List<Character> ALPHABET = new ArrayList<Character>(Arrays.asList('а','б','в','г','д','е','ж','з','и','й','к','л','м','н','о','п','р','с','т','у','ф','х','ц','ч','ш','щ','ь','ы','э','ю','я'));
    private static final int MOD = 961;
    private static final String[] FBP = {"ст","но","то","на","ен"};//Frequently bigrams from plaintext
    private static final Set<String> FORBBIGR = new HashSet<String>(Arrays.asList("ащ","пв","фж","аы","иы","йы","оы","цм","хж","цж","чж","щй","ьу","аь","кю","зэ","бф","гф","пд"));
     
    public static String readFile(String path) throws IOException{
        String text = "";
        StringBuilder sb = new StringBuilder();
        BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(path),"CP1251"));
        String s;
        while((s=br.readLine()) != null){
            sb = sb.append(s);
        }  
        text = sb.toString();
        text = text.replaceAll("[^а-яА-Я]", "");
        text = text.toLowerCase();
        text = text.replaceAll("ё", "е");  
        text = text.replaceAll("ъ", "ь");
        return text;
    }
    
    public static int[][] countBigram(String text){
        int len =text.length();
        int[][] count = new int[32][32];
        char[] arr = text.toCharArray();
        for (int i=1;i<len;i++){
            count[(int)arr[i-1]-1072][(int)arr[i]-1072]++;
        }
            
        return count;
    }
    
    public static String max(int[][] count){
        StringBuilder res = new StringBuilder();
        int m = Integer.MIN_VALUE;
        int a=0;
        int b=0;
        for(int i=0;i<31;i++)
            for(int j=0;j<32;j++)
                if (count[i][j]>m){
                    m = count[i][j];
                    a=i;
                    b=j;
                }
        count[a][b] = Integer.MIN_VALUE;
        res.append((char)(1072+a));
        res.append((char)(1072+b));
        return res.toString();
    }
    
    public static String[] fiveMostFreq(String text){
        int[][] count = countBigram(text);
        String[] res = new String[5];
        for(int i=0;i<5;i++)
            res[i]=max(count);
        return res;
    }
    
    public static int toCode(char c1, char c2){
        return (int)ALPHABET.indexOf(c1)*31 + (int)ALPHABET.indexOf(c2);
    }
    
    public static int toCode(String s){
        char[] arr = s.toCharArray();
        return toCode(arr[0],arr[1]);
    }
    
    public static String toBigram(int code){
        StringBuilder sb = new StringBuilder();
        sb.append(ALPHABET.get(code/31));
        sb.append(ALPHABET.get(code%31));
        return sb.toString();
    }
    
    public static String encrypt(String text, int a, int b){
        char[] arr = text.toCharArray();
        StringBuilder sb = new StringBuilder();
        int buff;
        for(int i=1; i<text.length();i+=2){
            buff = toCode(arr[i-1],arr[i]);
            buff = (a*buff + b)%MOD;
            sb.append(toBigram(buff));
        }
        return sb.toString();
    }
    
    public static String decrypt(String text, int a, int b){
        char[] arr = text.toCharArray();
        StringBuilder sb = new StringBuilder();
        int buff;
        for(int i=1;i<text.length();i+=2){
            buff = toCode(arr[i-1],arr[i]);
            buff = Math.floorMod(reverseEl(a,MOD)*(buff - b), MOD);
            sb.append(toBigram(buff));
        }
        return sb.toString();
    }
    
    public static int gcd(int a, int b){
        List<Integer> r = new ArrayList<>();
        r.add(a);
        r.add(b);
        int i=1;
        while (r.get(i)!=0){
            r.add(r.get(i-1)%r.get(i));
            i++;
        }
        return r.get(i-1);
    }
    
    public static int reverseEl(int a){
        return reverseEl(a,MOD);
    }
    
    public static int reverseEl(int a, int mod){
        List<Integer> r = new ArrayList<>();
        List<Integer> q = new ArrayList<>();
        List<Integer> u = new ArrayList<>();
        List<Integer> v = new ArrayList<>();
        r.add(mod);
        r.add(a);
        int i=1;
        while (r.get(i)!=0){
            r.add(r.get(i-1)%r.get(i));
            q.add(r.get(i-1)/r.get(i));
            i++;
        }
        u.add(1);
        u.add(0);
        v.add(0);
        v.add(1);
        for (int j=0; j<i-2;j++){
            u.add(u.get(j) - q.get(j)*u.get(j+1));
            v.add(v.get(j) - q.get(j)*v.get(j+1));
        }
        return Math.floorMod(v.get(i-1), mod);        
    }
    
    public static List<Integer> solveEquations(int a, int b, int mod){
        List<Integer> res = new ArrayList<>();
        int d = gcd(a,mod);
        if (Math.floorMod(a, mod)==0){
            return res;
        }
        if (d==1) {
            res.add(Math.floorMod(reverseEl(a,mod)*b, mod));
            return res;
        }else if(b%d!=0){
            return res;         
        }else {
            int newMod = mod/d;
            res.add(solveEquations(a/d,b/d,newMod).get(0));
            for(int i=1;i<d;i++){
                res.add(res.get(i-1)+newMod);
            }
        }
        return res;
    }
    
    public static boolean forbiddenBigram(String text, int limit){
        int counter = 0;
        for(int i=2;i<text.length();i++){
            if(FORBBIGR.contains(text.substring(i-2, i)))
                counter++;
        }
        return counter <= limit;
    }
    
    public static boolean isItText(String text, double precise){
        int[] count = new int[6];//о,а,е,ф,щ,ь
        double[] freq = new double[6];
        final double[] ideal = {10.983, 7.998, 8.483, 0.267, 0.361, 1.735}; 
        char[] t = text.toCharArray();
        for (int i=0;i<text.length();i++)
            switch ((int) t[i]) {
                case 1086:
                    count[0]++;
                    break;
                case 1072:
                    count[1]++;
                    break;
                case 1077:
                    count[2]++;
                    break;
                case 1092:
                    count[3]++;
                    break;
                case 1097:
                    count[4]++;
                    break;
                case 1100:
                    count[5]++;
                    break;
                default:
                    break;
            }

        for(int i=0;i<6;i++)
            freq[i]=((double)count[i]*100)/text.length();
        int flag=0;
        for(int i=0;i<6;i++){
            if(Math.abs(ideal[i]-freq[i])>precise)
                flag++;
        }
        return flag == 0;
    }
    
    public static int[] countLetter(char[] arr,int size){
        int[] count = new int[32];
        for(int i=0;i<31;i++)
            count[i]=0;
        for(int i=0;i<size;i++)
            count[(int)arr[i]-1072]++;
        return count;
    }
    
    public static float coincidenceIndex(String text){
        char[] arr = text.toCharArray();
        float res =0;
        final int size = text.length();
        int[] count = countLetter(arr,size);
        for(int i=0;i<31;i++)
            res = res + count[i]*(count[i]-1);
        res = res/(size*(size-1));
        return res;
    }
    
    public static boolean isItTextInd(String text, double precise){
        double coinInd = coincidenceIndex(text);
        double ideal = 0.05789416;
        return Math.abs(ideal-coinInd)<precise;
    }
    
    public static void main(String[] args) throws IOException{
        String ciphertext = "";
        try{
            ciphertext = readFile(PATH_TO_C);
        }
        catch(IOException ex){
            System.out.print(ex.getMessage());
        }
        String[] FBC = fiveMostFreq(ciphertext);//Frequently bigrams from ciphertext
        System.out.println(Arrays.toString(FBC));
        System.out.println(ciphertext);
        Map<Integer, Integer> keys = new HashMap<>();
        List<Integer> a;
        for (int l=0;l<5;l++)
            for (int x=0;x<5;x++)
                for (int i=0;i<5;i++)
                    for(int j=0;j<5;j++){
                        a = solveEquations(toCode(FBP[l])-toCode(FBP[x])+MOD,toCode(FBC[i])-toCode(FBC[j])+MOD,MOD);
                            for(int k: a)
                                keys.put(k, Math.floorMod(toCode(FBC[i])-k*toCode(FBP[l]), MOD));
                    }
        System.out.println(keys);
        List<String> plaintexts = new ArrayList<>();
        a = new ArrayList<>();
        Set<Integer> kSet = keys.keySet();
        for(int k:kSet){
            plaintexts.add(decrypt(ciphertext,k,keys.get(k)));
            a.add(k);
        }
        System.out.println(plaintexts.size());
        List<String> clear = new ArrayList<>();
        List<Integer> res = new ArrayList<>();
        for(int i =0;i<plaintexts.size();i++)
            if (isItText(plaintexts.get(i),7))
            {
                clear.add(plaintexts.get(i));
                res.add(a.get(i));
            } 
        System.out.println(clear.size());
        plaintexts.clear();
        List<Integer> res1 = new ArrayList<>();
        System.out.println("===================================");
        for(int i=0;i<clear.size();i++)
            if(isItTextInd(clear.get(i),0.01)){
                plaintexts.add(clear.get(i));
                res1.add(res.get(i));
            }
        for(String s:plaintexts)
            System.out.println(s);
        System.out.println(plaintexts.size());
        System.out.println(res1);
        System.out.println("===================================");
        if (!res1.isEmpty()){
            int A = res1.get(0);
            int B = keys.get(A);
            System.out.println("Key is : " + A + " " + B);
            String plaintext = decrypt(ciphertext, A, B);
            System.out.println(plaintext);
            try {
                try (FileWriter fw = new FileWriter(PATH_TO_WRITE)) {
                    fw.write(plaintext);
                    fw.close();
                }
            } catch (IOException ex) {
                System.out.println(ex.getMessage());
            }    
        }
       
    }
}
