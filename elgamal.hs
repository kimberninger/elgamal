-- |Haskell-Implementation des ElGamal-Verschlüsselungsverfahrens.
--
-- Stellt Typen für private und öffentliche Schlüssel sowie Funktionen zum
-- Generieren dieser und zum Ver- und Entschlüsseln von Nachrichten zur
-- Verfügung.
--
-- /Hinweis/: Die Typen 'PrivateKey' und 'PublicKey' enthalten zusätzlich zu den
-- aus der Vorlesung bekannten Zahlen jeweils noch die Primzahl @p@, in deren
-- Restgruppe gerechnet wird. Somit muss diese nicht jeder Funktion separat
-- übergeben werden. Die Konsolenausgabe erfolgt dennoch in der Darstellung aus
-- der Vorlesung.
--
-- /Hinweis/: Der Typ 'Secret', der das Chiffrat repräsentiert, besteht hier
-- nicht aus einem Tupel, sondern aus einer Liste von Tupeln, da eine Nachricht,
-- die länger als @p@ ist, zunächst in Teilbotschaften zerlegt wird. Die Liste
-- enthält dann die Verschlüsselungen all dieser.
module ElGamal where

import Data.Bits
import Data.List
import System.IO
import System.Random

-- |Repräsentiert einen privaten Schlüssel für das ElGamal-Verfahren.
--
-- Die erste ganze Zahl ist die Primzahl @p@, in deren Restklasse gerechnet
-- wird, die zweite ist eine zufällig gewählte Zahl @a@ wobei
--
-- > 0<=a && a<=p-1
type PrivateKey = (Integer,Integer)

-- |Repräsentiert einen öffentlichen Schlüssel für das ElGamal-Verfahren.
--
-- Die erste ganze Zahl ist die Primzahl @p@, in deren Restgruppe gerechnet
-- wird, die zweite der zufällig gewählte Erzeuger @g@ der Gruppe und die dritte
-- das Ergebnis von
--
-- > g^a `mod` p
--
-- @a@ ist hierbei die zweite Komponente des privaten Schlüssels.
type PublicKey  = (Integer,Integer,Integer)

-- |Repräsentiert eine Nachricht, kodiert als ganze Zahl.
type Message    = Integer

-- |Repräsentiert eine durch das ElGamal-Verfahren verschlüsselte Nachricht.
--
-- Das 'Secret' wird deshalb als Liste dargestellt, da die Nachricht vor dem
-- Verschlüsseln in Teilnachrichten zerbrochen wird, falls sie aus der
-- Restgruppe herausfallen würde.
type Secret     = [(Integer,Integer)]


-- |Fragt über die Kommandozeile eine zu verschlüsselnde Nachricht als Folge von
-- Ziffern ab, verschlüsselt und entschlüsselt diese mit Hilfe des ElGamal-
-- Verfahrens und gibt zuletzt die benutzten Schlüssel sowie die ver- und
-- entschlüsselte Nachricht aus.
main :: IO ()
main = do
    putStr "zu verschlüsselnde Nachricht (m): "
    hFlush stdout
    gen <- getStdGen
    message <- fmap read getLine
    let (private@(p,a),public@(_,g,h)) = generateKeys gen
    gen' <- newStdGen
    let secret  = encode gen' public message
        decoded = decode private secret
    mapM_ putStrLn [ "Primzahl (p):                " ++ show p
                   , "privater Schlüssel (sk):     " ++ show a
                   , "öffentlicher Schlüssel (pk): " ++ show (g,h)
                   , "Chiffrat:                    " ++ show secret
                   , "entschlüsseltes Chiffrat:    " ++ show decoded]

-- |Erhält einen 'RandomGen' sowie einen öffentlichen Schlüssel und eine
-- Nachricht, kodiert als ganze Zahl.
--
-- Liefert das Chiffrat als 'Secret'.
encode :: RandomGen g => g -> PublicKey -> Message -> Secret
encode gen key@(p,_,_) = encodeStep gen key . crackMessage p
    where encodeStep _ _ [] = []
          encodeStep gen key@(p,g,h) (m:ms) =
              let (num,gen') = randomR (0,p-1) gen
                  c1         = modPow g num p
                  c2         = ((m `mod` p) * modPow h num p) `mod` p
              in (c1,c2) : encodeStep gen' key ms

-- |Erhält einen privaten Schlüssel und ein Chiffrat.
--
-- Liefert das entschlüsselte Chiffrat als 'Message'.
decode :: PrivateKey -> Secret -> Message
decode (p,a) =
    let decodeFragment (c1,c2) =
            let x = p-1-a
            in modPow c1 x p * (c2 `mod` p) `mod` p
    in read . concatMap (show . decodeFragment)

-- |Erhält eine ganze Zahl @n@ und eine als ganze Zahl kodierte Nachricht.
--
-- Teilt die Nachricht so lange in Teilnachrichten auf, bis keine der
-- Teilnachrichten größer @n@ ist. Gibt diese dann als Liste zurück.
crackMessage :: Integer -> Message -> [Message]
crackMessage n message
    | message < n = [message]
    | otherwise   =
        let ns      = show message
            (n1,n2) = splitAt (length ns `div` 2) ns
        in crackMessage n (read n1) ++ crackMessage n (read n2)

-- |Erhält einen 'RandomGen' und erzeugt zufällig privaten und öffentlichen
-- Schlüssel.
generateKeys :: RandomGen g => g -> (PrivateKey, PublicKey)
generateKeys gen =
    let (p,p',gen') = generatePrimes gen
        (a,gen'')   = randomR (0,p-1) gen'
        (g,_)       = getGenerator gen'' p p'
        h           = modPow g a p
    in ((p,a),(p,g,h))

-- |Erhält einen 'RandomGen' und liefert zwei zufällige Primzahlen @p@ und @p'@
-- in der Größenordnung von 96 Bit, sodass gilt
--
-- > p = 2*p' + 1
generatePrimes :: RandomGen g => g -> (Integer, Integer, g)
generatePrimes gen =
    let (num,gen2)     = randomNumber gen 96
        (p',gen3)      = primeNextTo gen2 num
        p              = 2*p' + 1
        (result,gen4)  = isPrime gen3 p
    in if result
          then (p,p',gen4)
          else generatePrimes gen4

-- |Erhält einen 'RandomGen' sowie zwei Primzahlen @p@ und @p'@ mit
--
-- > p = 2*p' + 1
--
-- und liefert eine zufällige ganze Zahl @g@, wobei @g@ ein zufällig gewählter
-- Erzeuger der zyklischen Restgruppe Modulo @p@ ist.
getGenerator :: RandomGen g => g -> Integer -> Integer -> (Integer, g)
getGenerator gen p p' =
    let (g,gen') = randomR (2,p-1) gen
    in if modPow g 2 p /= 1 && modPow g p' p /= 1
          then (g,gen')
          else getGenerator gen' p p'

-- |Erhält drei ganze Zahlen @x@, @y@ und @n@. Berechnet
--
-- > x^y `mod` n
modPow :: Integer -> Integer -> Integer -> Integer
modPow x y n = modPowStep y x 1 n
    where modPowStep y b r n
              | y == 0    = r
              | odd y     = modPowStep (y`shiftR`1) (b*b`mod`n) (r*b`mod`n) n
              | otherwise = modPowStep (y`shiftR`1) (b*b`mod`n) r n

-- |Erhält eine ganze Zahl @n@, ein Tupel @(lo,hi)@ und einen 'RandomGen'.
--
-- Liefert eine Liste mit @n@ Elementen im Intervall @[lo,hi]@ sowie einen neuen
-- Zufallgenerator.
finiteRandomRs :: (RandomGen g, Random a) => Int -> (a, a) -> g -> ([a], g)
finiteRandomRs 0 _ gen = ([], gen)  
finiteRandomRs n (lo,hi) gen =
    let (value, gen')          = randomR (lo,hi) gen  
        (restOfList, finalGen) = finiteRandomRs (n-1) (lo,hi) gen'  
    in  (value:restOfList, finalGen)

-- |Erhält einen 'RandomGen' sowie eine ganze Zahl @n@ und liefert eine
-- zufällige ganze Zahl in der Größenordnung von @n@ Bit.
randomNumber :: RandomGen g => g -> Int -> (Integer, g)
randomNumber gen 0 = (0,gen)
randomNumber gen bitsize =
    let (nums,gen') = finiteRandomRs bitsize (0,bitsize) gen
    in (foldl1 (.|.) $ map bit nums,gen')

-- |Erhält einen 'RandomGen' sowie eine ganze Zahl @n@. Es wird die nächste
-- Primzahl größer @n@ zurückgeliefert.
primeNextTo :: RandomGen g => g -> Integer -> (Integer, g)
primeNextTo gen num
    | even num  = primeNextTo gen' $ num + 1
    | result    = (num,gen')
    | otherwise = primeNextTo gen' $ num + 2
    where (result,gen') = isPrime gen num

-- |Erhält einen 'RandomGen' sowie eine Zahl @n@. Prüft, ob @n@ eine Primzahl
-- ist.
--
-- Für Zahlen größer 10000 wird der Miller-Rabin-Test mit 50 Iterationen
-- angewandt.
--
-- Die Wahrscheinlichkeit, dass die Funktion in diesem Fall für eine
-- zusammengesetzte Zahl @n@ fälschlicherweise 'True' liefert, ist kleiner
-- @10^(-30)@.
isPrime :: RandomGen g => g -> Integer -> (Bool, g)
isPrime gen num
    | num == 1         = (False,gen)
    | num == 2         = (True,gen)
    | even num         = (False,gen)
    | num `mod` 5 == 0 = (False,gen)
    | num <= 10000     = (num `elem` takeWhile (<=num) primes,gen)
    | otherwise        = let (nums,gen') = finiteRandomRs 50 (1,num) gen
                         in (all (passesMillerRabin num) $ nub nums,gen')

-- |Unendliche Liste aller Primzahlen.
primes :: [Integer]
primes = sieve [2..]
    where sieve (x:xs) = x : sieve (filter (\p -> p `mod` x /= 0) xs)

-- |Erhält ganze Zahlen @n@ und @b@. Prüft, ob @n@ eine Pseudoprimzahl zur Basis
-- @b@ ist.
passesMillerRabin :: Integer -> Integer -> Bool
passesMillerRabin p b = mrStep (modPow b m p) 0
    where pMinusOne = p - 1
          a         = lowestSetBit pMinusOne
          m         = pMinusOne `shiftR` a
          mrStep z j
              | j == 0 && z == 1 = True
              | z == pMinusOne   = True
              | z == 1           = False
              | j+1 == a         = False
              | otherwise        = mrStep (modPow z 2 p) (j+1)

-- |Erhält eine Bitfolge und liefert die Position des ersten gesetzten Bits
-- beginnend mit @0@.
--
-- Für eine Folge ohne gesetztes Bit wird @-1@ zurückgegeben.
lowestSetBit :: (Num a , Bits a) => a -> Int
lowestSetBit 0 = -1
lowestSetBit n
    | testBit n 0 = 0
    | otherwise   = 1 + lowestSetBit (n `shiftR` 1)